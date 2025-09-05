package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
)

func makeOAuthProvidersMap(oauthProviders []oauth.OAuthProvider) map[string]oauth.OAuthProvider {
	oauthProvidersMap := make(map[string]oauth.OAuthProvider)
	for _, provider := range oauthProviders {
		oauthProvidersMap[provider.Name()] = provider
	}
	return oauthProvidersMap
}

type OAuthHandler struct {
	*AuthHandler
	userService    UserService
	oauthProviders map[string]oauth.OAuthProvider
}

func NewOAuthHandler(authHandler *AuthHandler, userService UserService, oauthProviders []oauth.OAuthProvider) *OAuthHandler {
	return &OAuthHandler{
		AuthHandler:    authHandler,
		userService:    userService,
		oauthProviders: makeOAuthProvidersMap(oauthProviders),
	}
}

func (h *OAuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth) error {
	user, err := h.userService.GetUserByID(ctx.Context(), userOAuth.UserID)
	if err != nil {
		// TODO: render user not found or disabled error
		return ctx.SendStatus(http.StatusForbidden)
	}

	if err := h.createUserSession(ctx, user, nil); err != nil {
		return render.RenderInternalError(ctx)
	}

	state := ctx.Query("state")
	queryParams, err := url.ParseQuery(state)
	if err != nil {
		return ctx.SendStatus(http.StatusBadRequest)
	}
	return redirect(ctx, "/authorize", fiber.Map{"service": queryParams.Get("service")})
}

func (h *OAuthHandler) handleOAuthLink(ctx *fiber.Ctx, userID uint, userOAuth *model.UserOAuth) error {
	return nil
}

func (h *OAuthHandler) handleOAuthRegister(ctx *fiber.Ctx, userOAuth *model.UserOAuth) error {
	if userOAuth.UserID == 0 {
		sessions.Set(ctx, sessions.SessionData{
			IP:        ctx.IP(),
			OAuthID:   userOAuth.ID,
			LoginTime: time.Now(),
		})
		return redirect(ctx, "/register/oauth", fiber.Map{"service": ctx.Query("service")})
	}
	return nil
}

func (h *OAuthHandler) GetOAuthCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	providerName := ctx.Params("provider")

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

	session := sessions.Get(ctx)
	if userOAuth.UserID != 0 {
		return h.handleOAuthLogin(ctx, userOAuth)
	}

	if session.UserID != 0 {
		return h.handleOAuthLink(ctx, session.UserID, userOAuth)
	}

	return h.handleOAuthRegister(ctx, userOAuth)
}
