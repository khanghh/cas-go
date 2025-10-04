package handlers

import (
	"fmt"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"golang.org/x/crypto/bcrypt"
)

const (
	MsgLoginSessionExpired   = "Session expired. Please log in again."
	MsgLoginWrongCredentials = "Invalid username or password."
	MsgLoginEmailConflict    = "Email already linked to another account."
	MsgLoginUnsupportedOAuth = "This OAuth provider is not supported."
)

// LoginHandler handles authentication and authorization
type LoginHandler struct {
	serviceRegistry  ServiceRegistry
	userService      UserService
	challengeService *twofactor.ChallengeService
	oauthProviders   []oauth.OAuthProvider
}

// NewLoginHandler returns a new instance of AuthHandler.
func NewLoginHandler(serviceRegistry ServiceRegistry, userService UserService, challengeService *twofactor.ChallengeService, oauthProviders []oauth.OAuthProvider) *LoginHandler {
	return &LoginHandler{
		serviceRegistry:  serviceRegistry,
		userService:      userService,
		challengeService: challengeService,
		oauthProviders:   oauthProviders,
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

func mapLoginError(errorCode string) string {
	switch errorCode {
	case "email_conflict":
		return MsgLoginEmailConflict
	case "session_expired":
		return MsgLoginSessionExpired
	case "unsupported_provider":
		return MsgLoginUnsupportedOAuth
	default:
		return ""
	}
}

func (h *LoginHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	errorCode := ctx.Query("error")

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return render.RenderLogin(ctx, render.LoginPageData{
			OAuthLoginURLs: h.getOAuthLoginURLs(serviceURL),
			LoginError:     mapLoginError(errorCode),
		})
	}

	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", fiber.Map{"service": serviceURL})
}

func (h *LoginHandler) PostLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return render.RenderBadRequestError(ctx)
	}

	pageData := render.LoginPageData{
		Identifier:     username,
		OAuthLoginURLs: h.getOAuthLoginURLs(serviceURL),
	}

	user, err := h.userService.GetUserByUsernameOrEmail(ctx.Context(), username)
	if err != nil {
		pageData.LoginError = MsgLoginWrongCredentials
		return render.RenderLogin(ctx, pageData)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		pageData.LoginError = MsgLoginWrongCredentials
		return render.RenderLogin(ctx, pageData)
	}

	session = createUserSession(ctx, user, nil)

	redirectURL := "/"
	if serviceURL != "" {
		redirectURL = fmt.Sprintf("/authorize?service=%s", serviceURL)
	}
	return handleLogin2FA(ctx, h.challengeService, &session, redirectURL)
}

func (h *LoginHandler) PostLogout(ctx *fiber.Ctx) error {
	return performLogout(ctx)
}
