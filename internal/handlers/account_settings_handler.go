package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"golang.org/x/crypto/bcrypt"
)

type AccountSettingsHandler struct {
	userService      UserService
	twofactorService TwoFactorService
	mailSender       mail.MailSender
}

func (h *AccountSettingsHandler) GetChangePassword(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	return render.RenderChangePassword(ctx, "")
}

func (h *AccountSettingsHandler) PostChangePassword(ctx *fiber.Ctx) error {
	currentPassword := ctx.FormValue("currentPassword")
	newPassword := ctx.FormValue("newPassword")

	session := sessions.Get(ctx)
	if !session.IsAuthenticated() {
		return redirect(ctx, "/login")
	}

	if !csrf.Verify(ctx) {
		return render.RenderChangePassword(ctx, MsgInvalidRequest)
	}

	user, err := h.userService.GetUserByID(ctx.Context(), session.UserID)
	if err != nil {
		return forceLogout(ctx, "")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return render.RenderChangePassword(ctx, ErrIncorrectPassword)
	}

	if err := validatePassword(newPassword); err != nil {
		return render.RenderChangePassword(ctx, err.Error())
	}

	if err = h.userService.UpdatePassword(ctx.Context(), user.Email, newPassword); err != nil {
		return render.RenderInternalServerError(ctx)
	}

	sessions.Destroy(ctx)
	return render.RenderPasswordUpdated(ctx)
}

func NewAccountSettingsHandler(userService UserService, twofactorService TwoFactorService, mailSender mail.MailSender) *AccountSettingsHandler {
	return &AccountSettingsHandler{
		userService:      userService,
		twofactorService: twofactorService,
		mailSender:       mailSender,
	}
}
