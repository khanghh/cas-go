package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/model"
	"golang.org/x/crypto/bcrypt"
)

// LoginHandler handles authentication and authorization
type LoginHandler struct {
	userService      UserService
	twoFactorService TwoFactorService
	oauthProviders   []oauth.OAuthProvider
}

// NewLoginHandler returns a new instance of AuthHandler.
func NewLoginHandler(userService UserService, twoFactorService TwoFactorService, oauthProviders []oauth.OAuthProvider) *LoginHandler {
	return &LoginHandler{
		userService:      userService,
		twoFactorService: twoFactorService,
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
	case "unsupported_provider":
		return MsgLoginUnsupportedOAuth
	case "tfa_failed":
		return MsgTwoFactorChallengeFailed
	case "login_locked":
		return MsgTooManyFailedLogin
	default:
		return ""
	}
}

func (h *LoginHandler) GetLogin(ctx *fiber.Ctx) error {
	serviceURL := sanitizeURL(ctx.Query("service"))
	errorCode := ctx.Query("error")

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return render.RenderLogin(ctx, render.LoginPageData{
			OAuthLoginURLs: h.getOAuthLoginURLs(serviceURL),
			ErrorMsg:       mapLoginError(errorCode),
		})
	}

	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", "service", serviceURL)
}

// handleLogin2FA triggers 2FA challenge if user has enabled 2FA
func (h *LoginHandler) handleLogin2FA(ctx *fiber.Ctx, session *sessions.Session, user *model.User, serviceURL string) error {
	redirectURL := "/"
	if serviceURL != "" {
		redirectURL = fmt.Sprintf("/authorize?service=%s", serviceURL)
	}

	sessionData := sessions.SessionData{
		IP:            ctx.IP(),
		UserID:        user.ID,
		LoginTime:     time.Now(),
		TwoFARequired: user.TwoFAEnabled,
	}
	if !user.TwoFAEnabled {
		session.Reset(sessionData)
		return redirect(ctx, redirectURL)
	}

	opts := twofactor.ChallengeOptions{
		RedirectURL: redirectURL,
		ExpiresIn:   5 * time.Minute,
	}
	subject := getChallengeSubject(ctx, session)
	ch, err := h.twoFactorService.CreateChallenge(ctx.Context(), &subject, opts)
	if errors.Is(err, twofactor.ErrTooManyAttemtps) {
		return redirect(ctx, "/login", "error", "login_locked")
	}

	sessionData.TwoFAChallengeID = ch.ID
	session.Reset(sessionData)
	return redirect(ctx, "/2fa/challenge", "cid", ch.ID)
}

func (h *LoginHandler) PostLogin(ctx *fiber.Ctx) error {
	serviceURL := sanitizeURL(ctx.Query("service"))
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	session := sessions.Get(ctx)
	if session.IsAuthenticated() {
		return ctx.Redirect("/")
	}

	pageData := render.LoginPageData{
		OAuthLoginURLs: h.getOAuthLoginURLs(serviceURL),
	}

	if !csrf.Verify(ctx) {
		pageData.ErrorMsg = MsgInvalidRequest
		return render.RenderLogin(ctx, pageData)
	}

	user, err := h.userService.GetUserByUsernameOrEmail(ctx.Context(), username)
	if err != nil {
		pageData.ErrorMsg = MsgLoginWrongCredentials
		return render.RenderLogin(ctx, pageData)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		pageData.ErrorMsg = MsgLoginWrongCredentials
		return render.RenderLogin(ctx, pageData)
	}

	return h.handleLogin2FA(ctx, session, user, serviceURL)
}

func (h *LoginHandler) PostLogout(ctx *fiber.Ctx) error {
	return forceLogout(ctx, "")
}
