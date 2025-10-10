package handlers

import (
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/oauth"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
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
	case "session_expired":
		return MsgLoginSessionExpired
	case "unsupported_provider":
		return MsgLoginUnsupportedOAuth
	case "tfa_failed":
		return MsgTwoFactorChallengeFailed
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
			ErrorMsg:       mapLoginError(errorCode),
			CSRFToken:      csrf.Get(session).Token,
		})
	}

	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", "service", serviceURL)
}

func (h *LoginHandler) handleLogin2FA(ctx *fiber.Ctx, session *sessions.Session, redirectURL string) error {
	if session.TwoFAChallengeID != "" {
		ch, err := h.twoFactorService.GetChallenge(ctx.Context(), session.TwoFAChallengeID)
		if err == nil && ch.CanVerify() {
			return redirect(ctx, "/2fa/challenge", "cid", session.TwoFAChallengeID)
		}
	}

	if redirectURL == "" {
		redirectURL = string(ctx.Context().URI().RequestURI())
	}
	opts := twofactor.ChallengeOptions{
		RedirectURL: redirectURL,
		ExpiresIn:   15 * time.Minute,
	}
	subject := getChallengeSubject(ctx, session)
	ch, err := h.twoFactorService.CreateChallenge(ctx.Context(), &subject, opts)
	if err != nil {
		return err
	}

	session.Save(sessions.SessionData{
		IP:               ctx.IP(),
		UserID:           session.UserID,
		LoginTime:        time.Now(),
		TwoFARequired:    true,
		TwoFAChallengeID: ch.ID,
	})
	return redirect(ctx, "/2fa/challenge", "cid", ch.ID)
}

func (h *LoginHandler) PostLogin(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
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
		pageData.CSRFToken = csrf.Get(session).Token
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

	session = createUserSession(ctx, user, nil)
	redirectURL := "/"
	if serviceURL != "" {
		redirectURL = fmt.Sprintf("/authorize?service=%s", serviceURL)
	}
	return h.handleLogin2FA(ctx, session, redirectURL)
}

func (h *LoginHandler) PostLogout(ctx *fiber.Ctx) error {
	return forceLogout(ctx)
}
