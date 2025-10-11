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
	"github.com/khanghh/cas-go/internal/users"
)

const (
	passwordResetCID = "password_reset_cid"
)

type ResetPasswordHandler struct {
	userService      UserService
	twoFactorService TwoFactorService
	mailSender       mail.MailSender
}

type ResetPasswordClaims struct {
	SessionID string `json:"sessionID"`
	Email     string `json:"email"`
}

func (h *ResetPasswordHandler) generateResetPasswordToken(ctx *fiber.Ctx, email string) (string, string, error) {
	subject := twofactor.Subject{IPAddress: ctx.IP()}
	opts := twofactor.ChallengeOptions{ExpiresIn: 5 * time.Minute}
	ch, err := h.twoFactorService.CreateChallenge(ctx.Context(), &subject, opts)
	if err != nil {
		return "", "", err
	}
	claims := ResetPasswordClaims{
		SessionID: sessions.Get(ctx).ID(),
		Email:     email,
	}
	token, err := h.twoFactorService.Token().Generate(ctx.Context(), ch, claims)
	if err != nil {
		return "", "", err
	}
	return ch.ID, token, nil
}

func (h *ResetPasswordHandler) verifyResetPasswordToken(ctx *fiber.Ctx, cid, token string) (*ResetPasswordClaims, error) {
	ch, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return nil, err
	}

	var claims ResetPasswordClaims
	err = h.twoFactorService.Token().Verify(ctx.Context(), ch, token, &claims)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func (h *ResetPasswordHandler) GetResetPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	cid, ok := session.Get(passwordResetCID).(string)
	if !ok {
		return render.RenderNotFoundError(ctx)
	}

	_, err := h.twoFactorService.GetChallenge(ctx.Context(), cid)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}

	csrfToken := csrf.Get(sessions.Get(ctx)).Token
	return render.RenderSetNewPassword(ctx, csrfToken, "")
}

func (h *ResetPasswordHandler) PostResetPassword(ctx *fiber.Ctx) error {
	token := ctx.Query("token")
	newPassword := ctx.FormValue("newPassword")

	csrfToken := csrf.Get(sessions.Get(ctx)).Token
	if !csrf.Verify(ctx) {
		return render.RenderSetNewPassword(ctx, csrfToken, "")
	}

	if err := validatePassword(newPassword); err != nil {
		return render.RenderSetNewPassword(ctx, csrfToken, err.Error())
	}

	cid, ok := sessions.Get(ctx).Get(passwordResetCID).(string)
	if !ok {
		return render.RenderNotFoundError(ctx)
	}

	claims, err := h.verifyResetPasswordToken(ctx, cid, token)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}

	err = h.userService.ResetPassword(ctx.Context(), claims.Email, newPassword)
	if err != nil {
		return render.RenderNotFoundError(ctx)
	}

	return render.RenderPasswordUpdated(ctx)
}

func (h *ResetPasswordHandler) GetForogtPassword(ctx *fiber.Ctx) error {
	return render.RenderForgotPassword(ctx, render.ForgotPasswordPageData{})
}

func (h *ResetPasswordHandler) PostForgotPassword(ctx *fiber.Ctx) error {
	email := ctx.FormValue("email")

	pageData := render.ForgotPasswordPageData{
		CSRFToken: csrf.Get(sessions.Get(ctx)).Token,
	}
	if err := validateEmail(email); err != nil {
		pageData.ErrorMsg = err.Error()
		return render.RenderForgotPassword(ctx, pageData)
	}

	user, err := h.userService.GetUserByEmail(ctx.Context(), email)
	if errors.Is(err, users.ErrUserNotFound) {
		pageData.ErrorMsg = err.Error()
		return render.RenderForgotPassword(ctx, pageData)
	}
	if err != nil {
		return err
	}

	cid, token, err := h.generateResetPasswordToken(ctx, email)
	if err != nil {
		if errorMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errorMsg
			return render.RenderForgotPassword(ctx, pageData)
		}
		return err
	}

	sessions.Get(ctx).Set(passwordResetCID, cid)
	resetPasswordLink := appendQuery(fmt.Sprintf("%s/reset-password", ctx.BaseURL()), "token", token)
	err = mail.SendResetPasswordLink(h.mailSender, user.Email, resetPasswordLink)
	if err != nil {
		return err
	}
	return render.RenderForgotPassword(ctx, render.ForgotPasswordPageData{EmailSent: true})
}

func NewResetPasswordHandler(userService UserService, twoFactorService TwoFactorService, mailSender mail.MailSender) *ResetPasswordHandler {
	return &ResetPasswordHandler{
		userService:      userService,
		twoFactorService: twoFactorService,
		mailSender:       mailSender,
	}
}
