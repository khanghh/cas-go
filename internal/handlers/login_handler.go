package handlers

import (
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"golang.org/x/crypto/bcrypt"
)

// LoginHandler handles authentication and authorization
type LoginHandler struct {
	*AuthHandler
	serviceRegistry ServiceRegistry
	userService     UserService
	oauthProviders  []oauth.OAuthProvider
}

// NewLoginHandler returns a new instance of AuthHandler.
func NewLoginHandler(authHandler *AuthHandler, serviceRegistry ServiceRegistry, userService UserService, oauthProviders []oauth.OAuthProvider) *LoginHandler {
	return &LoginHandler{
		AuthHandler:     authHandler,
		serviceRegistry: serviceRegistry,
		userService:     userService,
		oauthProviders:  oauthProviders,
	}
}

func (h *LoginHandler) getOAuthLoginURLs(serviceURL string) map[string]string {
	query := url.Values{
		"service": {serviceURL},
	}
	oauthLoginURLs := make(map[string]string)
	for _, provider := range h.oauthProviders {
		oauthLoginURLs[provider.Name()] = provider.GetAuthCodeURL(query.Encode())
	}
	return oauthLoginURLs
}

func (h *LoginHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	renew := ctx.QueryBool("renew")

	if renew {
		sessions.Destroy(ctx)
	}

	if serviceURL != "" {
		baseServiceURL, err := parseServiceURL(serviceURL)
		if err != nil {
			return ctx.Redirect("/login")
		}
		if _, err := h.serviceRegistry.GetService(ctx.Context(), baseServiceURL); err != nil {
			return ctx.Redirect("/login")
		}
	}

	session := sessions.Get(ctx)
	if !renew && session.UserID != 0 {
		if _, err := h.userService.GetUserByID(ctx.Context(), session.UserID); err == nil {
			return redirect(ctx, "/authorize", fiber.Map{"service": serviceURL})
		}
	}

	return render.RenderLogin(ctx, render.LoginPageData{
		OAuthLoginURLs: h.getOAuthLoginURLs(serviceURL),
	})
}

func (h *LoginHandler) PostLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	pageData := render.LoginPageData{Identifier: username}

	user, err := h.userService.GetUserByUsernameOrEmail(ctx.Context(), username)
	if err != nil {
		pageData.LoginError = "Invalid username or password"
		return render.RenderLogin(ctx, pageData)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		pageData.LoginError = "Invalid username or password"
		return render.RenderLogin(ctx, pageData)
	}

	if err := h.createLoginSession(ctx, user, nil); err != nil {
		return render.RenderInternalError(ctx)
	}
	return redirect(ctx, "/authorize", fiber.Map{"service": serviceURL})
}

func (h *LoginHandler) PostLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return ctx.Redirect("/login")
}
