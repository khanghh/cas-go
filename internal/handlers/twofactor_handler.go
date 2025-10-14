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
	pageData := render.VerifyOTPPageData{
		Email:    email,
		IsMasked: true,
		ErrorMsg: errorMsg,
	}
	return render.RenderVerifyOTP(ctx, pageData)
}

func mapTwoFactorError(err error) (string, bool) {
	if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
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
		return fmt.Sprintf(MsgInvalidOTP, verifyErr.AttemptsLeft), true
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
	encryptedState := ctx.Query("state")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	var state TwoFactorState
	if err := decryptState(ctx, encryptedState, &state); err != nil {
		return render.RenderNotFoundError(ctx)
	}
	if time.Since(time.Unix(state.Timestamp, 0)) > 5*time.Minute {
		return render.RenderNotFoundError(ctx)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	pageData := render.VerificationRequiredPageData{
		EmailEnabled: true,
		Email:        user.Email,
		IsMasked:     true,
	}
	return render.RenderVerificationRequired(ctx, pageData)
}

func (h *TwoFactorHandler) generateAndSendEmailOTP(ctx *fiber.Ctx, ch *twofactor.Challenge, sub twofactor.Subject, email string) error {
	otpCode, err := h.twoFactorService.OTP().Generate(ctx.Context(), ch, sub)
	if err != nil {
		return err
	}
	return mail.SendOTP(h.mailSender, email, otpCode)
}

func (h *TwoFactorHandler) handleChallengeSuccess(ctx *fiber.Ctx, session *sessions.Session, ch *twofactor.Challenge, sub twofactor.Subject) error {
	if session.TwoFARequired && session.TwoFAChallengeID == ch.ID {
		session.TwoFARequired = false
		session.TwoFASuccessAt = time.Now()
		session.Save()
	}
	return redirect(ctx, ch.CallbackURL, "cid", ch.ID)
}

func (h *TwoFactorHandler) PostChallenge(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")
	method := ctx.FormValue("method")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	var state TwoFactorState
	if err := decryptState(ctx, encryptedState, &state); err != nil {
		return render.RenderNotFoundError(ctx)
	}
	if time.Since(time.Unix(state.Timestamp, 0)) > 5*time.Minute {
		return render.RenderNotFoundError(ctx)
	}

	pageData := render.VerificationRequiredPageData{
		EmailEnabled: true,
		Email:        user.Email,
		IsMasked:     true,
	}
	if !csrf.Verify(ctx) {
		pageData.ErrorMsg = MsgInvalidRequest
		return render.RenderVerificationRequired(ctx, pageData)
	}

	sub := getChallengeSubject(ctx, session)
	ch, err := h.twoFactorService.CreateChallenge(ctx.Context(), sub, state.CallbackURL, 5*time.Minute)
	if err != nil {
		if msg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = msg
			return render.RenderVerificationRequired(ctx, pageData)
		}
		return err
	}

	if state.Action == "login" {
		session.TwoFAChallengeID = ch.ID
	}

	if method == "email" {
		if err = h.generateAndSendEmailOTP(ctx, ch, sub, user.Email); err == nil {
			return redirect(ctx, "/2fa/otp/verify", "cid", ch.ID)
		}
	} else {
		// TODO: handle other methods
		return render.RenderNotFoundError(ctx)
	}

	if msg, ok := mapTwoFactorError(err); ok {
		pageData.ErrorMsg = msg
		return render.RenderVerificationRequired(ctx, pageData)
	}
	return err
}

func (h *TwoFactorHandler) GetVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")

	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login")
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}

	sub := getChallengeSubject(ctx, session)
	if err := h.twoFactorService.ValidateChallenge(ctx.Context(), ch, sub); err != nil {
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
		return forceLogout(ctx, "")
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
		if errors.Is(err, twofactor.ErrChallengeSubjectMismatch) {
			return render.RenderNotFoundError(ctx)
		}
		if errors.Is(err, twofactor.ErrTooManyFailedAttempts) {
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
		err = h.generateAndSendEmailOTP(ctx, ch, subject, user.Email)
		if err != nil {
			return handleTwoFactorError(ctx, err)
		}
		return redirect(ctx, "/2fa/verify-otp", "cid", ch.ID)
	}

	_, err = h.twoFactorService.OTP().Verify(ctx.Context(), ch, subject, otp)
	if err != nil {
		return handleTwoFactorError(ctx, err)
	}

	return h.handleChallengeSuccess(ctx, session, ch, subject)
}

func NewTwoFactorHandler(twoFactorService TwoFactorService, userService UserService, mailSender mail.MailSender) *TwoFactorHandler {
	return &TwoFactorHandler{
		twoFactorService: twoFactorService,
		userService:      userService,
		mailSender:       mailSender,
	}
}
