package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/handlers/params"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
)

const (
	oauthActionLogin    = "login"
	oauthActionRegister = "register"
	oauthActionLink     = "link"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) (string, error)
	GetService(ctx context.Context, serviceUrl string) (*model.Service, error)
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	SetLastLoginTime(ctx context.Context, userID uint, lastLoginTime time.Time) error
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type AuthorizeService interface {
	GenerateServiceTicket(ctx context.Context, userId uint, serviceUrl string) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceUrl string, ticketId string, timestamp string, signature string) (bool, error)
}

type AuthState struct {
	ServiceUrl string
	Action     string
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

func xorEncrypt(data []byte, key string) []byte {
	keyLen := len(key)
	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encrypted[i] = data[i] ^ key[i%keyLen]
	}
	return encrypted
}

// encryptState encrypts the state before passing to the oauth provider
func (s *AuthHandler) encryptState(state AuthState) string {
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(state)
	encryptedState := xorEncrypt(buffer.Bytes(), s.stateEncryptionKey)
	return base64.URLEncoding.EncodeToString(encryptedState)
}

// decryptState decrypts the state previously encrypted passed to the oauth provider
func (s *AuthHandler) decryptState(encryptedState string) (*AuthState, error) {
	encryptedBytes, err := base64.URLEncoding.DecodeString(encryptedState)
	if err != nil {
		return nil, err
	}
	decryptedBytes := xorEncrypt(encryptedBytes, s.stateEncryptionKey)
	reader := strings.NewReader(string(decryptedBytes))
	var state AuthState
	err = gob.NewDecoder(reader).Decode(&state)
	if err != nil {
		return nil, err
	}
	return &state, err
}

func (h *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceUrl := params.GetString(ctx, "service")

	session := sessions.Get(ctx)
	if session.UserID != 0 {
		user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
		if user != nil && err == nil {
			return h.handleAuthorizeServiceAccess(ctx, user, serviceUrl)
		}
	}

	encryptedState := h.encryptState(AuthState{
		ServiceUrl: serviceUrl,
		Action:     oauthActionLogin,
	})

	// Render login page
	oauthLoginUrls := make(map[string]string)
	for providerName, provider := range h.oauthProviders {
		oauthLoginUrls[providerName] = provider.GetAuthCodeUrl(encryptedState)
	}
	return render.RenderLoginPage(ctx, serviceUrl, oauthLoginUrls)
}

func (h *AuthHandler) GetRegister(ctx *fiber.Ctx) error {
	encryptedState := h.encryptState(AuthState{
		Action: oauthActionRegister,
	})
	oauthLoginUrls := make(map[string]string)
	for providerName, provider := range h.oauthProviders {
		oauthLoginUrls[providerName] = provider.GetAuthCodeUrl(encryptedState)
	}
	return render.RenderRegisterPage(ctx, oauthLoginUrls)
}

func (h *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	return nil
}

func (h *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return ctx.Redirect("/")
}

func (h *AuthHandler) redirectLogin(ctx *fiber.Ctx, serviceUrl string) error {
	redirectUrl, _ := url.Parse(fmt.Sprintf("%s/login", ctx.BaseURL()))
	rawQuery := url.Values{"service": {serviceUrl}}
	redirectUrl.RawQuery = rawQuery.Encode()
	return ctx.Redirect(redirectUrl.String())
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, user *model.User, serviceUrl string) error {
	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), user.ID, serviceUrl)
	if err != nil {
		return err
	}

	callbackUrl := fmt.Sprintf("%s?ticket=%s", ticket.CallbackUrl, ticket.TicketId)
	return ctx.Redirect(callbackUrl)
}

func (h *AuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	user, err := h.userService.GetUserByID(ctx.Context(), userOAuth.UserID)
	if err != nil {
		// TODO: create user and link with userOAuth if not exists
		return err
	}

	session := sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	}
	sessions.Set(ctx, session)

	if err := h.userService.SetLastLoginTime(ctx.Context(), user.ID, session.LoginTime); err != nil {
		return err
	}

	return h.redirectLogin(ctx, state.ServiceUrl)
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
