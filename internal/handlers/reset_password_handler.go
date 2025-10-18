package handlers

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/captcha"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/internal/users"
)

type ResetPasswordHandler struct {
	userService      UserService
	twoFactorService TwoFactorService
	mailSender       mail.MailSender
}

type ResetPasswordClaims struct {
	Email     string `json:"email"`
	Timestamp int64  `json:"timestamp"`
}

func (h *ResetPasswordHandler) generateResetPasswordToken(ctx *fiber.Ctx, email string) (string, error) {
	sub := twofactor.Subject{IPAddress: ctx.IP()}
	claims := ResetPasswordClaims{Email: email, Timestamp: time.Now().Unix()}
	token, _, err := h.twoFactorService.Token().Create(ctx.Context(), sub, "", claims, 5*time.Minute)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (h *ResetPasswordHandler) verifyResetPasswordToken(ctx *fiber.Ctx, cid, token string) (ResetPasswordClaims, error) {
	var claims ResetPasswordClaims
	err := h.twoFactorService.Token().Verify(ctx.Context(), token, &claims)
	if err != nil {
		return claims, err
	}
	return claims, nil
}

func (h *ResetPasswordHandler) GetResetPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	token := ctx.Query("token")
	state := ctx.Query("state")

	if state != "" {
		var claims ResetPasswordClaims
		if err := decryptState(ctx, state, &claims); err != nil {
			return render.RenderNotFoundError(ctx)
		}
		return render.RenderSetNewPassword(ctx, "")
	}

	if token != "" {
		claims, err := h.verifyResetPasswordToken(ctx, "", token)
		if err != nil {
			return render.RenderNotFoundError(ctx)
		}
		session.SetExpiry(15 * time.Minute)
		return redirect(ctx, "/reset-password", "state", encryptState(ctx, claims))
	}

	return render.RenderNotFoundError(ctx)
}

func (h *ResetPasswordHandler) PostResetPassword(ctx *fiber.Ctx) error {
	encryptedState := ctx.Query("state")
	newPassword := ctx.FormValue("newPassword")

	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	if encryptedState == "" {
		return render.RenderNotFoundError(ctx)
	}

	var claims ResetPasswordClaims
	if err := decryptState(ctx, encryptedState, &claims); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	if err := captcha.Verify(ctx); err != nil {
		return render.RenderSetNewPassword(ctx, MsgInvalidCaptcha)
	}

	if !csrf.Verify(ctx) {
		return render.RenderSetNewPassword(ctx, MsgInvalidRequest)
	}

	if err := validatePassword(newPassword); err != nil {
		return render.RenderSetNewPassword(ctx, err.Error())
	}

	err := h.userService.UpdatePassword(ctx.Context(), claims.Email, newPassword)
	if err != nil {
		return err
	}

	session.Destroy()
	return render.RenderPasswordUpdated(ctx)
}

func (h *ResetPasswordHandler) GetForogtPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	return render.RenderForgotPassword(ctx, render.ForgotPasswordPageData{})
}

func (h *ResetPasswordHandler) PostForgotPassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	username := ctx.FormValue("username")
	email := ctx.FormValue("email")

	pageData := render.ForgotPasswordPageData{}
	if err := validateEmail(email); err != nil {
		pageData.ErrorMsg = err.Error()
		return render.RenderForgotPassword(ctx, pageData)
	}

	if err := captcha.Verify(ctx); err != nil {
		pageData.ErrorMsg = MsgInvalidCaptcha
		return render.RenderForgotPassword(ctx, pageData)
	}

	if !csrf.Verify(ctx) {
		pageData.ErrorMsg = MsgInvalidRequest
		return render.RenderForgotPassword(ctx, pageData)
	}

	user, err := h.userService.GetUserByEmail(ctx.Context(), email)
	if errors.Is(err, users.ErrUserNotFound) {
		pageData.ErrorMsg = MsgUserNotFound
		return render.RenderForgotPassword(ctx, pageData)
	}
	if err != nil {
		return err
	}

	if user.Username != username {
		pageData.ErrorMsg = MsgUserNotFound
		return render.RenderForgotPassword(ctx, pageData)
	}

	token, err := h.generateResetPasswordToken(ctx, email)
	if err != nil {
		if errorMsg, ok := mapTwoFactorError(err); ok {
			pageData.ErrorMsg = errorMsg
			return render.RenderForgotPassword(ctx, pageData)
		}
		return err
	}

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
