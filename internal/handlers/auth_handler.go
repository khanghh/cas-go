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
	oauthActionLogin = "login"
	oauthActionLink  = "link"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) error
	GetService(ctx context.Context, serviceUrl string) (*model.Service, error)
}

type UserService interface {
	GetUserById(ctx context.Context, userId uint) (*model.User, error)
}

type AuthorizeService interface {
	GenerateServiceTicket(ctx context.Context, user *model.User, service *model.Service) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceTicket string, timestamp string, signature string) (bool, error)
}

type OAuthService interface {
	OAuthProviders() []oauth.OAuthProvider
	GetOrCreateUserOAuth(ctx context.Context, providerName string, authCode string) (*model.UserOAuth, error)
	GetUserOAuths(ctx context.Context, userId uint) ([]*model.UserOAuth, error)
}

type AuthState struct {
	ServiceUrl string
	Action     string
}

type AuthHandler struct {
	serviceRegistry    ServiceRegistry
	authorizeService   AuthorizeService
	userService        UserService
	oauthService       OAuthService
	stateEncryptionKey string
}

// NewAuthHandler returns a new instance of AuthHandler.
func NewAuthHandler(serviceRegistry ServiceRegistry, authorizeService AuthorizeService, userService UserService, oauthService OAuthService) *AuthHandler {
	return &AuthHandler{
		serviceRegistry:  serviceRegistry,
		authorizeService: authorizeService,
		userService:      userService,
		oauthService:     oauthService,
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

func (h *AuthHandler) generateOAuthLoginUrls(ctx *fiber.Ctx, oauthProviders []oauth.OAuthProvider, state AuthState) map[string]string {
	encryptedState := h.encryptState(state)
	oauthLoginUrls := make(map[string]string)
	for _, provider := range oauthProviders {
		oauthCallbackUrl, _ := url.JoinPath(ctx.BaseURL(), "oauth", provider.Name(), "callback")
		oauthLoginUrls[provider.Name()] = provider.GetOAuthUrl(oauthCallbackUrl, encryptedState)
	}
	return oauthLoginUrls
}

func (h *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceUrl := params.GetString(ctx, "service")

	session := sessions.Get(ctx)
	if session.UserId != 0 {
		return h.handleAuthorizeServiceAccess(ctx, session.UserId, serviceUrl)
	}

	// Render login page
	oauthLoginUrls := h.generateOAuthLoginUrls(ctx, h.oauthService.OAuthProviders(), AuthState{
		ServiceUrl: serviceUrl,
		Action:     oauthActionLogin,
	})
	return render.RenderLoginPage(ctx, serviceUrl, oauthLoginUrls)
}

func (h *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	return nil
}

func (h *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	err := session.Destroy()
	if err != nil {
		return err
	}
	return ctx.Redirect("/")
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, userId uint, serviceUrl string) error {
	user, err := h.userService.GetUserById(ctx.Context(), userId)
	if err != nil {
		return render.RenderUnauthorizedServiceErrorPage(ctx, 2)
	}

	service, err := h.serviceRegistry.GetService(ctx.Context(), serviceUrl)
	if err != nil {
		return render.RenderUnauthorizedServiceErrorPage(ctx, 2)
	}

	ticket, err := h.authorizeService.GenerateServiceTicket(ctx.Context(), user, service)
	if err != nil {
		return err
	}

	callbackUrl := fmt.Sprintf("%s?ticket=%s", service.CallbackUrl, ticket.TicketId)
	return ctx.Redirect(callbackUrl)
}

func (h *AuthHandler) redirectLogin(ctx *fiber.Ctx, serviceUrl string) error {
	redirectUrl, _ := url.Parse(fmt.Sprintf("%s/login", ctx.BaseURL()))
	rawQuery := url.Values{"service": {serviceUrl}}
	redirectUrl.RawQuery = rawQuery.Encode()
	return ctx.Redirect(redirectUrl.String())
}

func (h *AuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	user, err := h.userService.GetUserById(ctx.Context(), userOAuth.UserId)
	if err != nil {
		return err
	}

	sessionInfo := sessions.SessionInfo{
		IP:        ctx.IP(),
		UserId:    user.ID,
		LoginTime: time.Now(),
	}
	err = sessions.Get(ctx).Save(sessionInfo)
	if err != nil {
		return err
	}

	return h.redirectLogin(ctx, state.ServiceUrl)
}

func (c *AuthHandler) handleOAuthLink(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	return nil
}

func (h *AuthHandler) GetOAuthCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	provider := ctx.Params("provider")

	userOAuth, err := h.oauthService.GetOrCreateUserOAuth(ctx.Context(), provider, code)
	if err != nil {
		return err
	}

	state, err := h.decryptState(ctx.Query("state"))
	if err != nil {
		return err
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
