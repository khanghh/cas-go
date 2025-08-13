package handlers

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/handlers/params"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) (string, error)
	GetService(ctx context.Context, serviceURL string) (*model.Service, error)
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
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

func (h *AuthHandler) redirectLogin(ctx *fiber.Ctx, serviceURL string, renew bool) error {
	if renew {
		sessions.Destroy(ctx)
	}
	redirectURL, _ := url.Parse(fmt.Sprintf("%s/login", ctx.BaseURL()))
	if serviceURL != "" {
		rawQuery := url.Values{"service": {serviceURL}}
		redirectURL.RawQuery = rawQuery.Encode()
	}
	return ctx.Redirect(redirectURL.String())
}

func (h *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceURL := params.GetString(ctx, "service")

	session := sessions.Get(ctx)
	if session.UserID != 0 {
		// TODO: handle login without provide serviceURL
		user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
		if err == nil {
			return h.handleAuthorizeServiceAccess(ctx, user, serviceURL)
		}
	}

	// Render login page
	encryptedState := h.encryptState(AuthState{
		ServiceURL: serviceURL,
		Action:     oauthActionLogin,
	})
	oauthLoginURLs := make(map[string]string)
	for providerName, provider := range h.oauthProviders {
		oauthLoginURLs[providerName] = provider.GetAuthCodeURL(encryptedState)
	}
	return render.RenderLogin(ctx, serviceURL, oauthLoginURLs)
}

func (h *AuthHandler) GetRegister(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.OAuthID != 0 {
		userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
		if err != nil {
			return err
		}
		return render.RenderOAuthRegister(ctx, userOAuth)
	}
	return render.RenderRegister(ctx)
}

func (h *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	return nil
}

func (h *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return ctx.Redirect("/login")
}

// parseServiceURL parses the service URL and returns the base URL without query
func parseServiceURL(serviceURL string) (string, error) {
	parsed, err := url.Parse(serviceURL)
	if err != nil {
		return "", err
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String(), nil
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, user *model.User, serviceURL string) error {
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
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), user.ID, callbackURL)
	if err != nil {
		return err
	}

	redirectURL := fmt.Sprintf("%s?ticket=%s", ticket.CallbackURL, ticket.TicketID)
	return ctx.Redirect(redirectURL)
}

func (h *AuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	// TODO: if user was not registered then redirect to login page with error message
	user, err := h.userService.GetUserByID(ctx.Context(), userOAuth.UserID)
	if err != nil {
		return h.redirectLogin(ctx, state.ServiceURL, true)
	}

	// handle login success
	loginTime := time.Now()
	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		OAuthID:   userOAuth.ID,
		LoginTime: loginTime,
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

	state, err := h.decryptState(encryptedState)
	if err != nil {
		return err
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
		Provider:  providerName,
		ProfileID: oauthUserInfo.ID,
		Email:     oauthUserInfo.Email,
		Name:      oauthUserInfo.Name,
		Picture:   oauthUserInfo.Picture,
	})
	if err != nil {
		return nil
	}

	switch state.Action {
	case oauthActionLogin:
		return h.handleOAuthLogin(ctx, userOAuth, state)
	case oauthActionLink:
		return h.handleOAuthLink(ctx, userOAuth, state)
	default:
		return fmt.Errorf("unknown action: %s", state.Action)
	}
}
