package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/handlers/params"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
	"golang.org/x/crypto/bcrypt"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) (string, error)
	GetService(ctx context.Context, serviceURL string) (*model.Service, error)
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	CreateUser(ctx context.Context, user *model.User) error
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error)
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type AuthorizeService interface {
	GenerateServiceTicket(ctx context.Context, userID uint, serviceURL string) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceURL string, ticketID string, timestamp string, signature string) (bool, error)
}

// AuthHandler handles authentication and authorization
type AuthHandler struct {
	serviceRegistry    ServiceRegistry
	authorizeService   AuthorizeService
	userService        UserService
	oauthProviders     map[string]oauth.OAuthProvider
	stateEncryptionKey string
}

func makeOAuthProvidersMap(oauthProviders []oauth.OAuthProvider) map[string]oauth.OAuthProvider {
	oauthProvidersMap := make(map[string]oauth.OAuthProvider)
	for _, provider := range oauthProviders {
		oauthProvidersMap[provider.Name()] = provider
	}
	return oauthProvidersMap
}

// NewAuthHandler returns a new instance of AuthHandler.
func NewAuthHandler(serviceRegistry ServiceRegistry, authorizeService AuthorizeService, userService UserService, oauthProviders []oauth.OAuthProvider, stateEncryptionKey string) *AuthHandler {
	return &AuthHandler{
		serviceRegistry:    serviceRegistry,
		authorizeService:   authorizeService,
		userService:        userService,
		oauthProviders:     makeOAuthProvidersMap(oauthProviders),
		stateEncryptionKey: stateEncryptionKey,
	}
}

func (h *AuthHandler) redirect(ctx *fiber.Ctx, location string, params fiber.Map) error {
	url, err := url.Parse(location)
	if err != nil {
		return err
	}
	query := url.Query()
	for key, value := range params {
		if value != nil && value != "" {
			query.Set(key, fmt.Sprintf("%v", value))
		}
	}
	url.RawQuery = query.Encode()
	return ctx.Redirect(url.String())
}

func (h *AuthHandler) redirectLogin(ctx *fiber.Ctx, serviceURL string, renew bool) error {
	queries := fiber.Map{"service": serviceURL}
	if renew {
		queries["renew"] = true
	}
	return h.redirect(ctx, "/login", queries)
}

func (h *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	renew := ctx.QueryBool("renew")

	encryptedState := h.encryptState(AuthState{
		ServiceURL: serviceURL,
		Action:     actionOAuthLogin,
	})

	session := sessions.Get(ctx)
	if renew {
		sessions.Destroy(ctx)
	} else if session.UserID != 0 {
		if user, err := h.userService.GetUserByID(ctx.Context(), session.UserID); err == nil {
			return h.handleAuthorizeServiceAccess(ctx, user, serviceURL)
		}
	} else if session.OAuthID != 0 && session.UserID == 0 {
		return h.redirect(ctx, "/onboarding", fiber.Map{"state": encryptedState})
	}

	oauthLoginURLs := make(map[string]string)
	for providerName, provider := range h.oauthProviders {
		oauthLoginURLs[providerName] = provider.GetAuthCodeURL(encryptedState)
	}
	return render.RenderLogin(ctx, serviceURL, oauthLoginURLs)
}

func (h *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	return nil
}

func (h *AuthHandler) GetRegister(ctx *fiber.Ctx) error {
	return render.RenderRegister(ctx)
}

func (h *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return ctx.Redirect("/login")
}

func (h *AuthHandler) GetOnboarding(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return ctx.Redirect("/")
	}
	if session.OAuthID != 0 {
		userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
		if err == nil && userOAuth.UserID == 0 {
			return render.RenderOnboarding(ctx, render.OnboardingForm{
				Username: fmt.Sprintf("user%d", userOAuth.ID),
				Email:    userOAuth.Email,
				FullName: userOAuth.DisplayName,
				Picture:  userOAuth.Picture,
			})
		}
	}

	return h.redirectLogin(ctx, "", true)
}

func (h *AuthHandler) PostOnboarding(ctx *fiber.Ctx) error {
	state, _ := h.decryptState(ctx.Query("state"))
	session := sessions.Get(ctx)
	if session.OAuthID == 0 {
		return h.redirectLogin(ctx, state.ServiceURL, true)
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil || userOAuth.UserID != 0 {
		return h.redirectLogin(ctx, state.ServiceURL, true)
	}

	var form render.OnboardingForm
	if err := ctx.BodyParser(&form); err != nil {
		return render.RenderInternalError(ctx)
	}

	if userOAuth.Email != "" {
		form.Email = userOAuth.Email
	}

	if err := validateOnboardingForm(&form); err != nil {
		form.FullName = userOAuth.DisplayName
		return render.RenderOnboarding(ctx, form)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	user := &model.User{
		Username:      form.Username,
		DisplayName:   form.FullName,
		Email:         form.Email,
		EmailVerified: form.Email == userOAuth.Email,
		Password:      string(passwordHash),
		OAuths:        []model.UserOAuth{*userOAuth},
	}

	if err = h.userService.CreateUser(ctx.Context(), user); err != nil {
		form.Password = ""
		switch {
		case errors.Is(err, users.ErrUserNameExists):
			form.UsernameError = "Username is already taken."
			return render.RenderOnboarding(ctx, form)
		case errors.Is(err, users.ErrUserEmailExists):
			form.EmailError = "Email is already registered."
			return render.RenderOnboarding(ctx, form)
		default:
			slog.Error("Failed to create user", "error", err)
			return render.RenderInternalError(ctx)
		}
	}

	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		OAuthID:   userOAuth.ID,
		LoginTime: time.Now(),
	})

	return h.handleAuthorizeServiceAccess(ctx, user, params.GetString(ctx, "service"))
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, u *model.User, serviceURL string) error {
	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	baseServiceURL, err := parseServiceURL(serviceURL)
	if err != nil {
		return render.RenderUnauthorizedError(ctx)
	}

	service, err := h.serviceRegistry.GetService(ctx.Context(), baseServiceURL)
	if err != nil {
		return render.RenderUnauthorizedError(ctx)
	}

	callbackURL := baseServiceURL
	if service.StripQuery {
		callbackURL = serviceURL
	}
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), u.ID, callbackURL)
	if err != nil {
		return err
	}

	redirectURL := fmt.Sprintf("%s?ticket=%s", ticket.CallbackURL, ticket.TicketID)
	return ctx.Redirect(redirectURL)
}

func (h *AuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	if userOAuth.UserID == 0 {
		sessions.Set(ctx, sessions.SessionData{
			IP:        ctx.IP(),
			OAuthID:   userOAuth.ID,
			LoginTime: time.Now(),
		})
		return h.redirect(ctx, "/onboarding", fiber.Map{"state": ctx.Query("state")})
	}

	user, err := h.userService.GetUserByID(ctx.Context(), userOAuth.UserID)
	if err != nil {
		return h.redirectLogin(ctx, state.ServiceURL, true)
	}

	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	})
	return h.handleAuthorizeServiceAccess(ctx, user, state.ServiceURL)
}

func (c *AuthHandler) handleOAuthLink(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	return nil
}

func (h *AuthHandler) GetOAuthCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	providerName := ctx.Params("provider")
	encryptedState := ctx.Query("state")

	provider, ok := h.oauthProviders[providerName]
	if !ok {
		return fmt.Errorf("Unsupported OAuth provider: %s", providerName)
	}

	oauthToken, err := provider.ExchangeToken(ctx.Context(), code)
	if err != nil {
		return err
	}

	oauthUserInfo, err := provider.GetUserInfo(ctx.Context(), oauthToken)
	if err != nil {
		return err
	}

	userOAuth, err := h.userService.GetOrCreateUserOAuth(ctx.Context(), &model.UserOAuth{
		Provider:    providerName,
		ProfileID:   oauthUserInfo.ID,
		Email:       oauthUserInfo.Email,
		DisplayName: oauthUserInfo.Name,
		Picture:     oauthUserInfo.Picture,
	})
	if err != nil {
		return nil
	}

	state, err := h.decryptState(encryptedState)
	if err != nil {
		return err
	}
	switch state.Action {
	case actionOAuthLogin:
		return h.handleOAuthLogin(ctx, userOAuth, &state)
	case actionOAuthLink:
		return h.handleOAuthLink(ctx, userOAuth, &state)
	default:
		return fmt.Errorf("unknown action: %s", state.Action)
	}
}
