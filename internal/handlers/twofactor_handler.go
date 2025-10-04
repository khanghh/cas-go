package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
)

const (
	MsgInvalidRequest        = "Invalid request. Please try again."
	MsgOTPCodeEmpty          = "OTP code cannot be empty."
	MsgInvalidOTP            = "Incorrect OTP. You have %d attempt(s) left."
	MsgTooManyOTPRequested   = "You've requested too many OTPs. Please try again later."
	MsgOTPRequestRateLimited = "Please wait before requesting another OTP."
	MsgUserLockedReason      = "%s. Please try again after %d minutes."
	MsgTooManyFailedAttempts = "Too many failed attempts. Please try again later."
)

var (
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
)

type TwoFactorHandler struct {
	challengeService *twofactor.ChallengeService
	userService      *users.UserService
	mailSender       mail.MailSender
}

func generateCSRFToken() string {
	const tokenLength = 32
	b := make([]byte, tokenLength)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (h *TwoFactorHandler) handleGenerateAndSendEmailOTP(ctx *fiber.Ctx, user *model.User, ch *twofactor.Challenge) error {
	session := sessions.Get(ctx)
	otpCode, err := h.challengeService.OTP().Generate(ctx.Context(), ch, session.UserID)
	if errors.Is(err, twofactor.ErrOTPRequestLimitReached) {
		return render.RenderVerificationRequired(ctx, render.VerificationRequiredPageData{
			ChallengeID:  ch.ID,
			EmailEnabled: true,
			Email:        user.Email,
			IsMasked:     true,
			MethodError:  MsgTooManyOTPRequested,
		})
	}
	if err != nil {
		return err
	}

	if err := mail.SendOTP(h.mailSender, user.Email, otpCode); err != nil {
		return err
	}

	return redirect(ctx, "/2fa/otp/verify", fiber.Map{"cid": ch.ID})
}

func (h *TwoFactorHandler) renderVerifyOTP(ctx *fiber.Ctx, email string, errorMsg string) error {
	session := sessions.Get(ctx)
	session.CSRFToken = generateCSRFToken()
	sessions.Set(ctx, session)
	pageData := render.VerifyOTPPageData{
		Email:       email,
		IsMasked:    true,
		CSRFToken:   session.CSRFToken,
		VerifyError: errorMsg,
	}
	return render.RenderVerifyOTP(ctx, pageData)
}

func handleLogin2FA(ctx *fiber.Ctx, challengeService *twofactor.ChallengeService, session *sessions.SessionData, redirectURL string) error {
	if session.IsAuthenticated() {
		return ctx.Redirect(redirectURL)
	}

	if session.TwoFAChallengeID != "" {
		ch, err := challengeService.GetChallenge(ctx.Context(), session.TwoFAChallengeID)
		if err == nil && ch.CanVerify() {
			return redirect(ctx, "/2fa/challenge", fiber.Map{"cid": session.TwoFAChallengeID})
		}
	}

	if redirectURL == "" {
		redirectURL = string(ctx.Context().URI().RequestURI())
	}
	opts := twofactor.ChallengeOptions{
		UserID:      session.UserID,
		Binding:     twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()},
		RedirectURL: redirectURL,
		ExpiresIn:   15 * time.Minute,
	}
	ch, err := challengeService.CreateChallenge(ctx.Context(), opts)
	if err != nil {
		return err
	}

	sessions.Set(ctx, sessions.SessionData{
		IP:               ctx.IP(),
		UserID:           session.UserID,
		LoginTime:        time.Now(),
		TwoFARequired:    true,
		TwoFAChallengeID: ch.ID,
	})
	return redirect(ctx, "/2fa/challenge", fiber.Map{"cid": ch.ID})
}

func mapTwoFactorError(err error) (string, bool) {
	if errors.Is(err, twofactor.ErrOTPRequestLimitReached) {
		return MsgTooManyOTPRequested, true
	}
	if errors.Is(err, twofactor.ErrTooManyAttemtps) {
		return MsgTooManyFailedAttempts, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestRateLimited) {
		return MsgOTPRequestRateLimited, true
	}
	var verifyErr *twofactor.VerifyFailError
	if errors.As(err, &verifyErr) {
		return fmt.Sprintf(MsgInvalidOTP, verifyErr.AttemtpsLeft), true
	}
	var lockedErr *twofactor.UserLockedError
	if errors.As(err, &lockedErr) {
		return fmt.Sprintf(MsgUserLockedReason, lockedErr.Reason, int(time.Until(lockedErr.Until).Minutes())), true
	}
	return "", false
}

func (h *TwoFactorHandler) GetChallenge(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login", nil)
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	binding := twofactor.BindingValues{user.ID, session.ID(), ctx.IP()}
	ch, err := h.challengeService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	if h.challengeService.ValidateChallenge(ctx.Context(), ch, binding) != nil {
		return render.RenderNotFoundError(ctx)
	}

	pageData := render.VerificationRequiredPageData{
		ChallengeID:  ch.ID,
		EmailEnabled: true,
		Email:        user.Email,
		IsMasked:     true,
	}
	return render.RenderVerificationRequired(ctx, pageData)
}

func (h *TwoFactorHandler) PostChallenge(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	method := ctx.FormValue("method")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login", nil)
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	ch, err := h.challengeService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	binding := twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()}
	if err := h.challengeService.ValidateChallenge(ctx.Context(), ch, binding); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	// TODO: handle other methods
	if method == "email" {
		return h.handleGenerateAndSendEmailOTP(ctx, user, ch)
	}

	return render.RenderNotFoundError(ctx)
}

func (h *TwoFactorHandler) GetVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login", nil)
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	ch, err := h.challengeService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	binding := twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()}
	if err := h.challengeService.ValidateChallenge(ctx.Context(), ch, binding); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	return h.renderVerifyOTP(ctx, user.Email, "")
}

func (h *TwoFactorHandler) PostVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	otp := ctx.FormValue("otp")
	resend := ctx.FormValue("resend") != ""
	csrf := ctx.FormValue("_csrf")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login", nil)
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	if !resend && otp == "" {
		return h.renderVerifyOTP(ctx, user.Email, MsgOTPCodeEmpty)
	}
	if csrf != session.CSRFToken {
		return h.renderVerifyOTP(ctx, user.Email, MsgInvalidRequest)
	}

	binding := twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()}
	ch, err := h.challengeService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	if !ch.CanVerify() {
		sessions.Destroy(ctx)
		return ctx.Redirect("/login")
	}

	if resend {
		otpCode, err := h.challengeService.OTP().Generate(ctx.Context(), ch, user.ID)
		if err != nil {
			if msg, ok := mapTwoFactorError(err); ok {
				return h.renderVerifyOTP(ctx, user.Email, msg)
			}
			return err
		}
		if err := mail.SendOTP(h.mailSender, user.Email, otpCode); err != nil {
			return err
		}
		return h.renderVerifyOTP(ctx, user.Email, "")
	}

	err = h.challengeService.OTP().Verify(ctx.Context(), ch, session.UserID, binding, otp)
	if err != nil {
		if msg, ok := mapTwoFactorError(err); ok {
			return h.renderVerifyOTP(ctx, user.Email, msg)
		}
		return err
	}

	session.TwoFARequired = false
	sessions.Set(ctx, session)
	return redirect(ctx, ch.RedirectURL, nil)
}

func NewTwoFactorHandler(challengeService *twofactor.ChallengeService, userService *users.UserService, mailSender mail.MailSender) *TwoFactorHandler {
	return &TwoFactorHandler{
		challengeService: challengeService,
		userService:      userService,
		mailSender:       mailSender,
	}
}
