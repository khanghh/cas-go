package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

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
	twoFactorService *twofactor.TwofactorService
	mailSender       mail.MailSender
}

func NewRegisterHandler(userService UserService, twofactorService *twofactor.TwofactorService, mailSender mail.MailSender) *RegisterHandler {
	return &RegisterHandler{
		userService:      userService,
		twoFactorService: twofactorService,
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
		return render.RenderInternalError(ctx)
	}

	opts := twofactor.ChallengeOptions{ExpiresIn: 1 * time.Hour}
	ch, err := h.twoFactorService.CreateChallenge(ctx.Context(), opts)
	if err != nil {
		return render.RenderInternalError(ctx)
	}
	registerClaims := RegisterClaims{
		Username: username,
		Email:    email,
	}
	token, err := h.twoFactorService.JWT().GenerateToken(ctx.Context(), ch, registerClaims)
	if err != nil {
		return render.RenderInternalError(ctx)
	}
	verifyURL := fmt.Sprintf("%s/register/verify-email?token=%s", ctx.BaseURL(), token)
	if err := mail.SendRegisterVerification(h.mailSender, email, verifyURL); err != nil {
		return render.RenderInternalError(ctx)
	}
	return render.RenderRegisterVerifyEmail(ctx, email)
}

func (h *RegisterHandler) GetRegisterWithOAuth(ctx *fiber.Ctx) error {
	session := sessions.Get(ctx)
	if session.IsLoggedIn() {
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
	if session.IsLoggedIn() {
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
		IP:          ctx.IP(),
		UserID:      user.ID,
		LoginTime:   time.Now(),
		Last2FATime: time.Now(),
	})

	serviceURL := ctx.Query("service")
	if serviceURL == "" {
		return ctx.Redirect("/")
	}
	return redirect(ctx, "/authorize", fiber.Map{"service": serviceURL})
}

func (h *RegisterHandler) GetVerifyEmail(ctx *fiber.Ctx) error {
	token := ctx.Query("token")
	jwtChallenger := h.twoFactorService.JWT()

	var claims RegisterClaims
	err := jwtChallenger.VerifyToken(ctx.Context(), token, &claims)
	if err != nil {
		return render.RenderEmailVerificationFailure(ctx)
	}

	pendingUser, err := h.userService.GetPendingUser(ctx.Context(), claims.Username, claims.Email)
	if err != nil {
		return render.RenderEmailVerificationFailure(ctx)
	}

	pendingUser.EmailVerified = true
	if err := h.userService.AddUser(ctx.Context(), pendingUser); err != nil {
		return render.RenderInternalError(ctx)
	}

	return render.RenderEmailVerificationSuccess(ctx, claims.Email)
}
