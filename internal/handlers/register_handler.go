package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
	"golang.org/x/crypto/bcrypt"
)

type RegisterForm struct {
	Username string `form:"username"`
	Password string `form:"password"`
	Email    string `form:"email"`
}

func (form *RegisterForm) Validate() map[string]string {
	formErrors := make(map[string]string)
	if err := validateUsername(form.Username); err != nil {
		formErrors["username"] = err.Error()
	}

	if err := validatePassword(form.Password); err != nil {
		formErrors["password"] = err.Error()
	}

	if err := validateEmail(form.Email); err != nil {
		formErrors["email"] = err.Error()
	}
	return formErrors
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

func (h *RegisterHandler) GetOnboarding(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		return ctx.Redirect("/")
	}
	if session.OAuthID != 0 {
		userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
		if err == nil && userOAuth.UserID == 0 {
			return render.RenderOnboarding(ctx, render.OnboardingPageData{
				Username: fmt.Sprintf("user%d", userOAuth.ID),
				FullName: userOAuth.DisplayName,
				Email:    userOAuth.Email,
			})
		}
	}
	return redirect(ctx, "/login", nil)
}

func (h *RegisterHandler) PostOnboarding(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.UserID != 0 {
		// TODO: render bad request error
		return ctx.SendStatus(http.StatusBadRequest)
	}

	if session.OAuthID == 0 {
		// TODO: render session expired error
		return ctx.SendStatus(http.StatusUnauthorized)
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil || userOAuth.UserID != 0 {
		// TODO: render bad request error
		return ctx.SendStatus(http.StatusBadRequest)
	}

	// validate registration form
	var form RegisterForm
	if err := ctx.BodyParser(&form); err != nil {
		return render.RenderInternalError(ctx)
	}
	pageData := render.OnboardingPageData{
		Username: form.Username,
		Email:    userOAuth.Email,
		FullName: userOAuth.DisplayName,
		Picture:  userOAuth.Picture,
	}
	form.Email = userOAuth.Email
	if errs := form.Validate(); len(errs) > 0 {
		pageData.UsernameError = errs["username"]
		pageData.PasswordError = errs["password"]
		pageData.EmailError = errs["email"]
		return render.RenderOnboarding(ctx, pageData)
	}

	// create user
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
	if err != nil {
		return render.RenderInternalError(ctx)
	}
	user := &model.User{
		Username:      form.Username,
		DisplayName:   userOAuth.DisplayName,
		Email:         userOAuth.Email,
		EmailVerified: true,
		Password:      string(passwordHash),
		Picture:       userOAuth.Picture,
		OAuths:        []model.UserOAuth{*userOAuth},
	}

	if err = h.userService.CreateUser(ctx.Context(), user); err != nil {
		form.Password = ""
		switch {
		case errors.Is(err, users.ErrUserNameExists):
			pageData.UsernameError = "Username is already taken."
			return render.RenderOnboarding(ctx, pageData)
		case errors.Is(err, users.ErrUserEmailExists):
			pageData.EmailError = "Email is already registered."
			return render.RenderOnboarding(ctx, pageData)
		default:
			slog.Error("Failed to create user", "error", err)
			return render.RenderInternalError(ctx)
		}
	}

	if err := h.createLoginSession(ctx, user, nil); err != nil {
		return render.RenderInternalError(ctx)
	}
	return redirectInternal(ctx, "/login")
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

	// parse and validate registration form
	var form RegisterForm
	if err := ctx.BodyParser(&form); err != nil {
		return ctx.SendStatus(http.StatusBadRequest)
	}
	pageData := render.RegisterPageData{
		Username: form.Username,
		Email:    form.Email,
	}
	if formErrs := form.Validate(); len(formErrs) > 0 {
		pageData.UsernameError = formErrs["username"]
		pageData.EmailError = formErrs["email"]
		pageData.PasswordError = formErrs["password"]
		return render.RenderRegister(ctx, pageData)
	}

	// create user
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
	if err != nil {
		return render.RenderInternalError(ctx)
	}
	user := model.User{
		Username: form.Username,
		Password: string(passwordHash),
		Email:    form.Email,
	}
	if err := h.userService.CreateUser(ctx.Context(), &user); err != nil {
		if errors.Is(err, users.ErrUserNameExists) {
			pageData.UsernameError = "Username is already taken"
			return render.RenderRegister(ctx, pageData)
		} else if errors.Is(err, users.ErrUserEmailExists) {
			pageData.EmailError = "Email is already registered"
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
