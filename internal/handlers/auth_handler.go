package handlers

import (
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/handlers/params"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/model"
)

type AuthHandler struct {
	authenticateSvc *auth.AuthenticateService
	authorizeSvc    *auth.AuthorizeService
}

// NewAuthHandler returns a new instance of AuthHandler.
func NewAuthHandler(authenticateSvc *auth.AuthenticateService, authorizeService *auth.AuthorizeService) *AuthHandler {
	return &AuthHandler{
		authenticateSvc: authenticateSvc,
		authorizeSvc:    authorizeService,
	}
}

func (h *AuthHandler) renderLoginPage(ctx *fiber.Ctx, serviceUrl string, oauthProviders []auth.OAuthProvider, state string) error {
	oauthLoginUrls := make(map[string]string)
	for _, provider := range oauthProviders {
		oauthCallbackUrl, _ := url.JoinPath(ctx.BaseURL(), "oauth", provider.Name(), "callback")
		oauthUrl := provider.GetOAuthUrl(oauthCallbackUrl, state)
		oauthLoginUrls[provider.Name()] = oauthUrl
	}
	return render.RenderLoginPage(ctx, serviceUrl, oauthLoginUrls)
}

func (h *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	serviceUrl := params.GetString(ctx, "service")

	if session.UserId != 0 {
		return h.handleAuthorizeService(ctx, serviceUrl)
	}

	// Render login page
	encryptedState := auth.EncryptOAuthState(auth.OAuthState{
		Service: serviceUrl,
		Action:  auth.OAuthActionLogin,
	})
	return h.renderLoginPage(ctx, serviceUrl, h.authenticateSvc.OAuthProviders(), encryptedState)
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

func (h *AuthHandler) handleAuthorizeService(ctx *fiber.Ctx, serviceUrl string) error {
	s := sessions.Get(ctx)
	user, err := h.authenticateSvc.GetUserByID(ctx.Context(), s.UserId)
	if err != nil {
		return render.RenderUnauthorizedServiceErrorPage(ctx, 2)
	}

	redirectUrl, err := h.authorizeSvc.AuthorizeUserService(ctx.Context(), user, serviceUrl)
	if err != nil {
		return render.RenderUnauthorizedServiceErrorPage(ctx, 3)
	}

	return ctx.Redirect(redirectUrl)
}

func (h *AuthHandler) redirectLogin(ctx *fiber.Ctx, serviceUrl string) error {
	redirectUrl, _ := url.Parse(fmt.Sprintf("%s/login", ctx.BaseURL()))
	rawQuery := url.Values{"service": {serviceUrl}}
	redirectUrl.RawQuery = rawQuery.Encode()
	return ctx.Redirect(redirectUrl.String())
}

func (h *AuthHandler) handleOAuthLogin(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *auth.OAuthState) error {
	user, err := h.authenticateSvc.OAuthLogin(ctx.Context(), userOAuth)
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

	return h.redirectLogin(ctx, state.Service)
}

func (c *AuthHandler) handleOAuthLink(ctx *fiber.Ctx, userOAuth *model.UserOAuth, state *auth.OAuthState) error {
	return nil
}

func (c *AuthHandler) GetOAuthCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	provider := ctx.Params("provider")

	userOAuth, err := c.authenticateSvc.GetUserOAuth(ctx.Context(), provider, code)
	if err != nil {
		return err
	}

	state, err := auth.DecryptOAuthState(ctx.Query("state"))
	if err != nil {
		return err
	}

	switch state.Action {
	case auth.OAuthActionLogin:
		return c.handleOAuthLogin(ctx, userOAuth, state)
	case auth.OAuthActionLink:
		return c.handleOAuthLink(ctx, userOAuth, state)
	default:
		return fmt.Errorf("unknown action: %s", state.Action)
	}
}
