package handlers

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/model"
)

var (
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
)

type TwoFactorHandler struct {
	twoFactorService TwoFactorService
	userService      UserService
	mailSender       mail.MailSender
}

func (h *TwoFactorHandler) renderVerifyOTP(ctx *fiber.Ctx, email string, errorMsg string) error {
	session := sessions.Get(ctx)
	pageData := render.VerifyOTPPageData{
		Email:     email,
		IsMasked:  true,
		CSRFToken: csrf.Get(session).Token,
		ErrorMsg:  errorMsg,
	}
	return render.RenderVerifyOTP(ctx, pageData)
}

func mapTwoFactorError(err error) (string, bool) {
	if errors.Is(err, twofactor.ErrTooManyAttemtps) {
		return MsgTooManyFailedAttempts, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestLimitReached) {
		return MsgTooManyOTPRequested, true
	}
	if errors.Is(err, twofactor.ErrOTPRequestRateLimited) {
		return MsgOTPRequestRateLimited, true
	}
	var verifyErr *twofactor.AttemptFailError
	if errors.As(err, &verifyErr) {
		return fmt.Sprintf(MsgInvalidOTP, verifyErr.AttemtpsLeft), true
	}
	return "", false
}

func getChallengeSubject(ctx *fiber.Ctx, session *sessions.Session) twofactor.Subject {
	return twofactor.Subject{
		UserID:    session.UserID,
		SessionID: session.ID(),
		IPAddress: ctx.IP(),
		UserAgent: ctx.Get("User-Agent"),
	}
}

func (h *TwoFactorHandler) GetChallenge(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject) != nil {
		return render.RenderNotFoundError(ctx)
	}

	pageData := render.VerificationRequiredPageData{
		ChallengeID:  ch.ID,
		EmailEnabled: true,
		Email:        user.Email,
		IsMasked:     true,
		CSRFToken:    csrf.Get(session).Token,
	}
	return render.RenderVerificationRequired(ctx, pageData)
}

func (h *TwoFactorHandler) handleGenerateAndSendEmailOTP(ctx *fiber.Ctx, user *model.User, ch *twofactor.Challenge) error {
	subject := getChallengeSubject(ctx, sessions.Get(ctx))
	otpCode, err := h.twoFactorService.OTP().Generate(ctx.Context(), ch, subject)
	if err != nil {
		if msg, ok := mapTwoFactorError(err); ok {
			return render.RenderVerificationRequired(ctx, render.VerificationRequiredPageData{
				ChallengeID:  ch.ID,
				EmailEnabled: true,
				Email:        user.Email,
				IsMasked:     true,
				ErrorMsg:     msg,
			})
		}
		return err
	}

	if err := mail.SendOTP(h.mailSender, user.Email, otpCode); err != nil {
		return err
	}

	return redirect(ctx, "/2fa/otp/verify", "cid", ch.ID)
}

func (h *TwoFactorHandler) PostChallenge(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	method := ctx.FormValue("method")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	if !csrf.Verify(ctx) {
		pageData := render.VerificationRequiredPageData{
			EmailEnabled: true,
			Email:        user.Email,
			IsMasked:     true,
			CSRFToken:    csrf.Get(session).Token,
			ErrorMsg:     MsgInvalidRequest,
		}
		return render.RenderVerificationRequired(ctx, pageData)
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject); err != nil {
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
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	return h.renderVerifyOTP(ctx, user.Email, "")
}

func (h *TwoFactorHandler) PostVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	otp := ctx.FormValue("otp")
	resend := ctx.FormValue("resend") != ""

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return err
	}

	if !resend && otp == "" {
		return h.renderVerifyOTP(ctx, user.Email, MsgOTPCodeEmpty)
	}
	if !csrf.Verify(ctx) {
		return h.renderVerifyOTP(ctx, user.Email, MsgInvalidRequest)
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	subject := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, subject); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	handleTwoFactorError := func(ctx *fiber.Ctx, err error) error {
		if errors.Is(err, twofactor.ErrSubjectMismatch) {
			return render.RenderNotFoundError(ctx)
		}
		if errors.Is(err, twofactor.ErrTooManyAttemtps) {
			if !session.IsAuthenticated() {
				return forceLogout(ctx, "tfa_failed")
			}
			return ctx.Redirect("/")
		}
		if msg, ok := mapTwoFactorError(err); ok {
			return h.renderVerifyOTP(ctx, user.Email, msg)
		}
		return err
	}

	if resend {
		otpCode, err := h.twoFactorService.OTP().Generate(ctx.Context(), ch, subject)
		if err != nil {
			return handleTwoFactorError(ctx, err)
		}
		if err := mail.SendOTP(h.mailSender, user.Email, otpCode); err != nil {
			return err
		}
		return h.renderVerifyOTP(ctx, user.Email, "")
	}

	err = h.twoFactorService.OTP().Verify(ctx.Context(), ch, subject, otp)
	if err != nil {
		return handleTwoFactorError(ctx, err)
	}

	if session.TwoFARequired {
		session.TwoFARequired = false
		session.TwoFASuccessAt = time.Now()
		session.Save()
	}
	return redirect(ctx, ch.RedirectURL)
}

func NewTwoFactorHandler(twoFactorService TwoFactorService, userService UserService, mailSender mail.MailSender) *TwoFactorHandler {
	return &TwoFactorHandler{
		twoFactorService: twoFactorService,
		userService:      userService,
		mailSender:       mailSender,
	}
}
