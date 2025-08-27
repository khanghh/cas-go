package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
)

var (
	MsgUsernameTaken   = "Username is already taken."
	MsgEmailRegistered = "Email is already registered."
)

type RegisterForm struct {
	Username string `form:"username"`
	Password string `form:"password"`
	Email    string `form:"email"`
}

type RegisterHandler struct {
	*AuthHandler
	userService UserService
}

func NewRegisterHandler(authHandler *AuthHandler, userService UserService) *RegisterHandler {
	return &RegisterHandler{
		AuthHandler: authHandler,
		userService: userService,
	}
}

func validateRegisterForm(username string, password string, email string) map[string]string {
	formErrors := make(map[string]string)
	if err := validateUsername(username); err != nil {
		formErrors["username"] = err.Error()
	}

	if err := validatePassword(password); err != nil {
		formErrors["password"] = err.Error()
	}

	if err := validateEmail(email); err != nil {
		formErrors["email"] = err.Error()
	}
	return formErrors
}

func (h *RegisterHandler) GetRegister(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return ctx.Redirect("/")
	}
	return render.RenderRegister(ctx, render.RegisterPageData{})
}

func (h *RegisterHandler) PostRegister(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return ctx.SendStatus(http.StatusBadRequest)
	}

	var (
		username = ctx.FormValue("username")
		password = ctx.FormValue("password")
		email    = ctx.FormValue("email")
	)

	pageData := render.RegisterPageData{
		Username:   username,
		Email:      email,
		FormErrors: validateRegisterForm(username, password, email),
	}
	if len(pageData.FormErrors) > 0 {
		return render.RenderRegister(ctx, pageData)
	}

	user := model.User{
		Username:      username,
		DisplayName:   username,
		Email:         email,
		EmailVerified: false,
	}
	if err := h.userService.CreateUser(ctx.Context(), &user, password); err != nil {
		if errors.Is(err, users.ErrUserNameExists) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderRegister(ctx, pageData)
		} else if errors.Is(err, users.ErrUserEmailExists) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderRegister(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return render.RenderInternalError(ctx)
	}

	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	})
	return redirect(ctx, "/authorize", fiber.Map{"service": ctx.Query("service")})
}

func (h *RegisterHandler) GetRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return ctx.Redirect("/")
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	return render.RenderOAuthRegister(ctx, render.RegisterPageData{
		Email:         userOAuth.Email,
		FullName:      userOAuth.DisplayName,
		Picture:       userOAuth.Picture,
		OAuthProvider: userOAuth.Provider,
	})
}

func (h *RegisterHandler) PostRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return ctx.Redirect("/")
	}

	if session.OAuthID == 0 {
		return render.RenderInternalError(ctx)
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return render.RenderInternalError(ctx)
	}

	var (
		username = ctx.FormValue("username")
		password = ctx.FormValue("password")
	)

	pageData := render.RegisterPageData{
		Username:   username,
		Email:      userOAuth.Email,
		FullName:   userOAuth.DisplayName,
		Picture:    userOAuth.Picture,
		FormErrors: validateRegisterForm(username, password, userOAuth.Email),
	}
	if len(pageData.FormErrors) > 0 {
		return render.RenderOAuthRegister(ctx, pageData)
	}

	user := model.User{
		Username:      username,
		DisplayName:   userOAuth.DisplayName,
		Email:         userOAuth.Email,
		EmailVerified: true,
		Picture:       userOAuth.Picture,
		OAuths:        []model.UserOAuth{*userOAuth},
	}
	if err := h.userService.CreateUser(ctx.Context(), &user, password); err != nil {
		if errors.Is(err, users.ErrUserNameExists) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderOAuthRegister(ctx, pageData)
		} else if errors.Is(err, users.ErrUserEmailExists) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderOAuthRegister(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return err
	}

	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	})
	return redirect(ctx, "/authorize", fiber.Map{"service": ctx.Query("service")})
}
