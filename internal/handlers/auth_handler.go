package handlers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/model"
)

type AuthHandler struct {
	authorizeService AuthorizeService
	userService      UserService
	twoFactorService TwoFactorService
}

func NewAuthHandler(authorizeService AuthorizeService, userService UserService, twofactorService TwoFactorService) *AuthHandler {
	return &AuthHandler{
		authorizeService: authorizeService,
		userService:      userService,
		twoFactorService: twofactorService,
	}
}

func (h *AuthHandler) createUserSession(ctx *fiber.Ctx, user *model.User, userOAuth *model.UserOAuth) sessions.SessionData {
	session := sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	}
	if userOAuth != nil {
		session.OAuthID = userOAuth.ID
		session.Last2FATime = time.Now()
	}
	sessions.Reset(ctx, &session)
	return session
}

func (h *AuthHandler) start2FAChallenge(ctx *fiber.Ctx, session *sessions.SessionData, redirectURL string) error {
	if redirectURL == "" {
		redirectURL = string(ctx.Context().URI().RequestURI())
	}

	if session.ChallengeID != "" {
		ch, err := h.twoFactorService.GetChallenge(session.ChallengeID)
		if err == nil && ch.Status() == twofactor.ChallengeStatusPending {
			return redirect(ctx, "/2fa/challenge", fiber.Map{"cid": session.ChallengeID})
		}
	}

	opts := twofactor.ChallengeOptions{
		UserID:      session.UserID,
		Binding:     twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()},
		RedirectURL: redirectURL,
		ExpiresIn:   5 * time.Minute,
	}
	ch, err := h.twoFactorService.CreateChallenge(opts)
	if err != nil {
		return err
	}
	session.ChallengeID = ch.ID
	sessions.Set(ctx, *session)
	return redirect(ctx, "/2fa/challenge", fiber.Map{"cid": ch.ID})
}

func (h *AuthHandler) handleAuthorizeServiceAccess(ctx *fiber.Ctx, user *model.User, serviceURL string) error {
	baseServiceURL, err := parseServiceURL(serviceURL)
	if err != nil {
		return render.RenderDeniedError(ctx)
	}

	service, err := h.authorizeService.GetService(ctx.Context(), baseServiceURL)
	if err != nil {
		return render.RenderDeniedError(ctx)
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

func (h *AuthHandler) GetAuthorize(ctx *fiber.Ctx) error {
	serviceURL := ctx.Query("service")
	if serviceURL == "" {
		return render.RenderNotFoundError(ctx)
	}

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login", fiber.Map{"service": serviceURL})
	}

	if session.IsRequire2FA() {
		return h.start2FAChallenge(ctx, &session, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return render.RenderDeniedError(ctx)
	}
	return h.handleAuthorizeServiceAccess(ctx, user, serviceURL)
}

func (h *AuthHandler) GetHome(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return performLogout(ctx)
	}
	if session.IsRequire2FA() {
		return h.start2FAChallenge(ctx, &session, "")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return performLogout(ctx)
	}

	return render.RenderHomePage(ctx, render.HomePageData{
		Username: user.Username,
		FullName: user.DisplayName,
		Email:    user.Email,
	})
}
