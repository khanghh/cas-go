package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/params"
)

func makeOAuthProvidersMap(oauthProviders []oauth.OAuthProvider) map[string]oauth.OAuthProvider {
	oauthProvidersMap := make(map[string]oauth.OAuthProvider)
	for _, provider := range oauthProviders {
		oauthProvidersMap[provider.Name()] = provider
	}
	return oauthProvidersMap
}

type OAuthHandler struct {
	*BaseAuthHandler
	userService    UserService
	oauthProviders map[string]oauth.OAuthProvider
}

func NewOAuthHandler(baseAuthHander *BaseAuthHandler, userService UserService, oauthProviders []oauth.OAuthProvider) *OAuthHandler {
	return &OAuthHandler{
		BaseAuthHandler: baseAuthHander,
		userService:     userService,
		oauthProviders:  makeOAuthProvidersMap(oauthProviders),
	}
}

func (h *OAuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	if userOAuth.UserID == 0 {
		sessions.Set(ctx, sessions.SessionData{
			IP:        ctx.IP(),
			OAuthID:   userOAuth.ID,
			LoginTime: time.Now(),
		})
		return h.redirect(ctx, "/register", fiber.Map{"state": ctx.Query("state")})
	}

	user, err := h.userService.GetUserByID(ctx.Context(), userOAuth.UserID)
	if err != nil {
		return h.redirectLogin(ctx, state.ServiceURL, true)
	}

	if err := h.handleLoginSuccess(ctx, user, userOAuth); err != nil {
		return render.RenderInternalError(ctx)
	}
	return h.redirectInternal(ctx, "/login")
}

func (c *OAuthHandler) handleOAuthLink(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *AuthState) error {
	return nil
}

func (h *OAuthHandler) GetOAuthLogin(ctx *fiber.Ctx) error {
	providerName := ctx.Params("provider")
	serviceURL := ctx.Query("service")
	if provider, ok := h.oauthProviders[providerName]; ok {
		encryptedState := h.encryptState(AuthState{
			ServiceURL: serviceURL,
			Action:     actionOAuthLogin,
			CreateTime: time.Now(),
		})
		return ctx.Redirect(provider.GetAuthCodeURL(encryptedState))
	}
	return ctx.SendStatus(http.StatusBadRequest)
}

func (h *OAuthHandler) GetOAuthCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	providerName := ctx.Params("provider")

	state, err := h.decryptState(ctx.Query("state"))
	if err != nil {
		return err
	}

	if time.Since(state.CreateTime) > params.AuthStateTimeout {
		return h.redirectLogin(ctx, state.ServiceURL, true)
	}

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

	switch state.Action {
	case actionOAuthLogin:
		return h.handleOAuthLogin(ctx, userOAuth, &state)
	case actionOAuthLink:
		return h.handleOAuthLink(ctx, userOAuth, &state)
	default:
		return fmt.Errorf("unknown action: %s", state.Action)
	}
}
