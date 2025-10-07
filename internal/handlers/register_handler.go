package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/users"
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
	userService UserService
	mailSender  mail.MailSender
}

func NewRegisterHandler(userService UserService, mailSender mail.MailSender) *RegisterHandler {
	return &RegisterHandler{
		userService: userService,
		mailSender:  mailSender,
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
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}
	return render.RenderRegister(ctx, render.RegisterPageData{CSRFToken: csrf.Get(session).Token})
}

type RegisterClaims struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	TimeStamp int64  `json:"timestamp"`
}

func (h *RegisterHandler) PostRegister(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	var (
		username = strings.ToLower(ctx.FormValue("username"))
		email    = strings.ToLower(ctx.FormValue("email"))
		password = ctx.FormValue("password")
	)

	pageData := render.RegisterPageData{Username: username, Email: email}
	if !csrf.Verify(ctx) {
		pageData.ErrorMsg = MsgInvalidRequest
		pageData.CSRFToken = csrf.Get(session).Token
		return render.RenderRegister(ctx, pageData)
	}
	pageData.FormErrors = validateRegisterForm(username, password, email)
	if len(pageData.FormErrors) > 0 {
		return render.RenderRegister(ctx, pageData)
	}

	userOpts := users.CreateUserOptions{
		Username: username,
		Email:    email,
		Password: password,
	}
	pendingUser, err := h.userService.RegisterUser(ctx.Context(), userOpts)
	if err != nil {
		if errors.Is(err, users.ErrUsernameTaken) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderRegister(ctx, pageData)
		} else if errors.Is(err, users.ErrEmailRegisterd) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderRegister(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return err
	}

	verifyURL := fmt.Sprintf("%s/register/verify?email=%s&token=%s", ctx.BaseURL(), email, pendingUser.ActiveToken)
	if err := mail.SendRegisterVerification(h.mailSender, email, verifyURL); err != nil {
		return err
	}

	return render.RenderRegisterVerifyEmail(ctx, email)
}

func (h *RegisterHandler) GetRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() || session.OAuthID == 0 {
		return ctx.Redirect("/login")
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return err
	}

	return render.RenderOAuthRegister(ctx, render.RegisterPageData{
		Email:         userOAuth.Email,
		FullName:      userOAuth.DisplayName,
		Picture:       userOAuth.Picture,
		OAuthProvider: userOAuth.Provider,
		CSRFToken:     csrf.Get(session).Token,
	})
}

func (h *RegisterHandler) PostRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() || session.OAuthID == 0 {
		return ctx.Redirect("/")
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return err
	}

	var (
		username = ctx.FormValue("username")
		password = ctx.FormValue("password")
	)

	pageData := render.RegisterPageData{
		Username:      username,
		Email:         userOAuth.Email,
		FullName:      userOAuth.DisplayName,
		Picture:       userOAuth.Picture,
		OAuthProvider: userOAuth.Provider,
	}
	if !csrf.Verify(ctx) {
		pageData.ErrorMsg = MsgInvalidRequest
		pageData.CSRFToken = csrf.Get(session).Token
		return render.RenderOAuthRegister(ctx, pageData)
	}
	pageData.FormErrors = validateRegisterForm(username, password, userOAuth.Email)
	if len(pageData.FormErrors) > 0 {
		return render.RenderOAuthRegister(ctx, pageData)
	}

	userOpts := users.CreateUserOptions{
		Username:  username,
		FullName:  userOAuth.DisplayName,
		Email:     userOAuth.Email,
		Picture:   userOAuth.Picture,
		UserOAuth: userOAuth,
		Password:  password,
	}
	user, err := h.userService.CreateUser(ctx.Context(), userOpts)
	if err != nil {
		if errors.Is(err, users.ErrUsernameTaken) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderOAuthRegister(ctx, pageData)
		} else if errors.Is(err, users.ErrEmailRegisterd) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderOAuthRegister(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return err
	}

	sessions.Get(ctx).Save(sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		LoginTime: time.Now(),
	})

	serviceURL := ctx.Query("service")
	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", "service", serviceURL)
}

func (h *RegisterHandler) GetRegisterVerify(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	token := ctx.Query("token")

	if _, err := h.userService.ApprovePendingUser(ctx.Context(), email, token); err != nil {
		return render.RenderEmailVerificationFailure(ctx)
	}

	return render.RenderEmailVerificationSuccess(ctx, email)
}
