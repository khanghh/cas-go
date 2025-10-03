package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/mail"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/render"
	"github.com/khanghh/cas-go/internal/twofactor"
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
	userService      UserService
	challengeService *twofactor.ChallengeService
	mailSender       mail.MailSender
}

func NewRegisterHandler(userService UserService, challengeService *twofactor.ChallengeService, mailSender mail.MailSender) *RegisterHandler {
	return &RegisterHandler{
		userService:      userService,
		challengeService: challengeService,
		mailSender:       mailSender,
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
	return render.RenderRegister(ctx, render.RegisterPageData{})
}

type RegisterClaims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
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

	pageData := render.RegisterPageData{
		Username:   username,
		Email:      email,
		FormErrors: validateRegisterForm(username, password, email),
	}
	if len(pageData.FormErrors) > 0 {
		return render.RenderRegister(ctx, pageData)
	}

	userOpts := users.CreateUserOptions{
		Username: username,
		Email:    email,
		Password: password,
	}
	_, err := h.userService.RegisterUser(ctx.Context(), userOpts)
	if err != nil {
		if errors.Is(err, users.ErrUserNameExists) {
			pageData.FormErrors["username"] = MsgUsernameTaken
			return render.RenderRegister(ctx, pageData)
		} else if errors.Is(err, users.ErrUserEmailExists) {
			pageData.FormErrors["email"] = MsgEmailRegistered
			return render.RenderRegister(ctx, pageData)
		}
		slog.Error("Failed to create user", "error", err)
		return render.RenderInternalServerError(ctx)
	}

	opts := twofactor.ChallengeOptions{ExpiresIn: 1 * time.Hour}
	ch, err := h.challengeService.CreateChallenge(ctx.Context(), opts)
	if err != nil {
		return render.RenderInternalServerError(ctx)
	}

	registerClaims := RegisterClaims{Username: username, Email: email}
	token, err := h.challengeService.JWT().GenerateToken(ctx.Context(), ch, registerClaims)
	if err != nil {
		return render.RenderInternalServerError(ctx)
	}

	verifyURL := fmt.Sprintf("%s/register/verify?email=%s&token=%s", ctx.BaseURL(), email, token)
	if err := mail.SendRegisterVerification(h.mailSender, email, verifyURL); err != nil {
		return render.RenderInternalServerError(ctx)
	}
	return redirect(ctx, "/register/verify", fiber.Map{"email": email})
}

func (h *RegisterHandler) GetRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return render.RenderInternalServerError(ctx)
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
	if session.IsLoggedIn() {
		return ctx.Redirect("/")
	}

	if session.OAuthID == 0 {
		return render.RenderInternalServerError(ctx)
	}

	userOAuth, err := h.userService.GetUserOAuthByID(ctx.Context(), session.OAuthID)
	if err != nil {
		return render.RenderInternalServerError(ctx)
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

	userOpts := users.CreateUserOptions{
		Username:  username,
		FullName:  userOAuth.DisplayName,
		Email:     userOAuth.Email,
		Picture:   userOAuth.Picture,
		UserOAuth: userOAuth,
	}
	user, err := h.userService.CreateUser(ctx.Context(), userOpts)
	if err != nil {
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

	serviceURL := ctx.Query("service")
	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", fiber.Map{"service": serviceURL})
}

func (h *RegisterHandler) GetRegisterVerify(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	token := ctx.Query("token")

	if _, err := h.userService.GetPendingUser(ctx.Context(), email); err != nil {
		return render.RenderNotFoundError(ctx)
	}

	if token == "" {
		return render.RenderRegisterVerifyEmail(ctx, email)
	}

	var claims RegisterClaims
	jwtChallenger := h.challengeService.JWT()
	if err := jwtChallenger.VerifyToken(ctx.Context(), token, &claims); err != nil {
		return render.RenderEmailVerificationFailure(ctx)
	}
	if claims.Email != email {
		return render.RenderEmailVerificationFailure(ctx)
	}

	if _, err := h.userService.ApprovePendingUser(ctx.Context(), email); err != nil {
		return err
	}

	return render.RenderEmailVerificationSuccess(ctx, claims.Email)
}
