package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/model"
)

type TwoFactorHandler struct {
	*AuthHandler
	twofactorService TwoFactorService
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
	otpCode, err := h.twoFactorService.PrepareOTP(session.UserID, ch)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	if err := mail.SendOTP(h.mailSender, user.Email, otpCode); err != nil {
		return render.RenderInternalError(ctx)
	}
	return redirect(ctx, "/2fa/otp/verify", fiber.Map{"cid": ch.ID})
}

func (h *TwoFactorHandler) renderVerifyOTP(ctx *fiber.Ctx, user *model.User, cid string, verifyErr error) error {
	session := sessions.Get(ctx)
	session.CSRFToken = generateCSRFToken()
	sessions.Set(ctx, session)
	errorMsg := ""
	if verifyErr != nil {
		errorMsg = verifyErr.Error()
	}
	pageData := render.VerifyOTPPageData{
		ChallengeID: cid,
		Email:       user.Email,
		IsMasked:    true,
		CSRFToken:   session.CSRFToken,
		VerifyError: errorMsg,
	}
	return render.RenderVerifyOTP(ctx, pageData)
}

func (h *TwoFactorHandler) GetChallenge(ctx *fiber.Ctx) error {
	cid := ctx.Query("cid")
	session := sessions.Get(ctx)
	if !session.IsLoggedIn() {
		return redirect(ctx, "/login", nil)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	ch, err := h.twofactorService.GetChallenge(cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	binding := twofactor.BindingValues{user.ID, session.ID(), ctx.IP()}
	if err := h.twoFactorService.ValidateChallenge(ch, binding); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	pageData := render.VerificationRequiredPageData{
		ChallengeID:  ch.ID,
		EmailEnabled: user.EmailVerified,
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
		return render.RenderInternalError(ctx)
	}

	ch, err := h.twofactorService.GetChallenge(cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	binding := twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()}
	if err := h.twoFactorService.ValidateChallenge(ch, binding); err != nil {
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
	if session.UserID == 0 {
		return redirect(ctx, "/login", nil)
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	ch, err := h.twofactorService.GetChallenge(cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	binding := twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()}
	if err := h.twoFactorService.ValidateChallenge(ch, binding); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	return h.renderVerifyOTP(ctx, user, cid, nil)
}

func (h *TwoFactorHandler) PostVerifyOTP(ctx *fiber.Ctx) error {
	cid := ctx.FormValue("cid")
	otp := ctx.FormValue("otp")
	csrf := ctx.FormValue("_csrf")

	session := sessions.Get(ctx)
	if session.UserID == 0 {
		return redirect(ctx, "/login", nil)
	}
	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	if csrf != session.CSRFToken {
		return h.renderVerifyOTP(ctx, user, cid, errors.New("Invalid request. Please try again."))
	}

	ch, err := h.twoFactorService.GetChallenge(cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}
	binding := twofactor.BindingValues{session.UserID, session.ID(), ctx.IP()}
	ret, err := h.twoFactorService.VerifyChallenge(session.UserID, ch, binding, otp)
	if err != nil {
		return h.renderVerifyOTP(ctx, user, cid, err)
	}

	if ret.Success {
		session.Last2FATime = time.Now()
		sessions.Set(ctx, session)
		return redirect(ctx, ch.RedirectURL, nil)
	}
	return h.renderVerifyOTP(ctx, user, cid, errors.New("Invalid OTP. Please try again."))
}

func NewTwoFactorHandler(authHander *AuthHandler, twofactorService TwoFactorService, mailSender mail.MailSender) *TwoFactorHandler {
	return &TwoFactorHandler{
		AuthHandler:      authHander,
		twofactorService: twofactorService,
		mailSender:       mailSender,
	}
}
