package render

import (
	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/csrf"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
)

func RenderInternalServerError(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusInternalServerError).Render("error-internal", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func RenderNotFoundError(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusNotFound).Render("error-not-found", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func RenderForbiddenError(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusForbidden).Render("error-forbidden", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func RenderBadRequestError(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusBadRequest).Render("error-bad-request", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func RenderLogin(ctx *fiber.Ctx, data LoginPageData) error {
	statusCode := fiber.StatusOK
	if data.ErrorMsg != "" {
		statusCode = fiber.StatusUnauthorized
	}
	return ctx.Status(statusCode).Render("login", fiber.Map{
		"siteName":          ctx.Locals("siteName"),
		"csrfToken":         csrf.Get(sessions.Get(ctx)).Token,
		"turnstileSiteKey":  ctx.Locals("turnstileSiteKey"),
		"identifier":        data.Identifier,
		"googleOAuthURL":    data.OAuthLoginURLs["google"],
		"facebookOAuthURL":  data.OAuthLoginURLs["facebook"],
		"discordOAuthURL":   data.OAuthLoginURLs["discord"],
		"microsoftOAuthURL": data.OAuthLoginURLs["microsoft"],
		"appleOAuthURL":     data.OAuthLoginURLs["apple"],
		"errorMsg":          data.ErrorMsg,
	})
}

func RenderRegister(ctx *fiber.Ctx, data RegisterPageData) error {
	return ctx.Render("register", fiber.Map{
		"siteName":         ctx.Locals("siteName"),
		"csrfToken":        csrf.Get(sessions.Get(ctx)).Token,
		"turnstileSiteKey": ctx.Locals("turnstileSiteKey"),
		"username":         data.Username,
		"email":            data.Email,
		"usernameError":    data.FormErrors["username"],
		"passwordError":    data.FormErrors["password"],
		"emailError":       data.FormErrors["email"],
		"errorMsg":         data.ErrorMsg,
	})
}

func RenderOAuthRegister(ctx *fiber.Ctx, data RegisterPageData) error {
	return ctx.Render("oauth-register", fiber.Map{
		"siteName":         ctx.Locals("siteName"),
		"csrfToken":        csrf.Get(sessions.Get(ctx)).Token,
		"turnstileSiteKey": ctx.Locals("turnstileSiteKey"),
		"username":         data.Username,
		"fullName":         data.FullName,
		"email":            data.Email,
		"picture":          data.Picture,
		"oauthProvider":    data.OAuthProvider,
		"usernameError":    data.FormErrors["username"],
		"passwordError":    data.FormErrors["password"],
		"emailError":       data.FormErrors["email"],
		"errorMsg":         data.ErrorMsg,
	})
}

func RenderDeniedError(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusForbidden).Render("error-denied", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func RenderProfilePage(ctx *fiber.Ctx, data ProfilePageData) error {
	displayName := data.FullName
	if displayName == "" {
		displayName = data.Username
	}
	return ctx.Render("profile", fiber.Map{
		"siteName":     ctx.Locals("siteName"),
		"displayName":  displayName,
		"email":        data.Email,
		"picture":      data.Picture,
		"twoFAEnabled": data.TwoFAEnabled,
	})
}

func RenderVerificationRequired(ctx *fiber.Ctx, data VerificationRequiredPageData) error {
	email := data.Email
	phone := formatPhone(data.Phone)
	if data.IsMasked {
		email = maskEmail(email)
		phone = maskPhone(phone)
	}
	return ctx.Render("verification-required", fiber.Map{
		"siteName":     ctx.Locals("siteName"),
		"csrfToken":    csrf.Get(sessions.Get(ctx)).Token,
		"emailEnabled": data.EmailEnabled,
		"smsEnabled":   data.SMSEnableled,
		"totpEnabled":  data.TOTPEnabled,
		"email":        email,
		"phone":        phone,
		"errorMsg":     data.ErrorMsg,
	})
}

func RenderVerifyOTP(ctx *fiber.Ctx, pageData VerifyOTPPageData) error {
	email := pageData.Email
	phone := formatPhone(pageData.Phone)
	if pageData.IsMasked {
		email = maskEmail(email)
		phone = maskPhone(phone)
	}

	emailOrPhone := email
	if email == "" {
		emailOrPhone = phone
	}
	return ctx.Render("verify-otp", fiber.Map{
		"siteName":     ctx.Locals("siteName"),
		"csrfToken":    csrf.Get(sessions.Get(ctx)).Token,
		"emailOrPhone": emailOrPhone,
		"errorMsg":     pageData.ErrorMsg,
	})
}

func RenderRegisterVerifyEmail(ctx *fiber.Ctx, email string) error {
	return ctx.Render("verify-email", fiber.Map{
		"siteName": ctx.Locals("siteName"),
		"email":    email,
	})
}

func RenderEmailVerificationSuccess(ctx *fiber.Ctx, email string) error {
	return ctx.Render("verify-email-result", fiber.Map{
		"siteName": ctx.Locals("siteName"),
		"success":  true,
		"email":    email,
	})
}

func RenderEmailVerificationFailure(ctx *fiber.Ctx) error {
	return ctx.Render("verify-email-result", fiber.Map{
		"siteName": ctx.Locals("siteName"),
		"success":  false,
	})
}

func RenderAuthorizeServiceAccess(ctx *fiber.Ctx, data AuthorizeServicePageData) error {
	return ctx.Render("authorize-service", fiber.Map{
		"siteName":    ctx.Locals("siteName"),
		"email":       data.Email,
		"serviceName": data.ServiceName,
		"serviceURL":  data.ServiceURL,
	})
}

func RenderForgotPassword(ctx *fiber.Ctx, pageData ForgotPasswordPageData) error {
	return ctx.Render("forgot-password", fiber.Map{
		"siteName":         ctx.Locals("siteName"),
		"csrfToken":        csrf.Get(sessions.Get(ctx)).Token,
		"turnstileSiteKey": ctx.Locals("turnstileSiteKey"),
		"email":            pageData.Email,
		"emailSent":        pageData.EmailSent,
		"errorMsg":         pageData.ErrorMsg,
	})
}

func RenderSetNewPassword(ctx *fiber.Ctx, errorMsg string) error {
	return ctx.Render("set-new-password", fiber.Map{
		"siteName":         ctx.Locals("siteName"),
		"csrfToken":        csrf.Get(sessions.Get(ctx)).Token,
		"turnstileSiteKey": ctx.Locals("turnstileSiteKey"),
		"errorMsg":         errorMsg,
	})
}

func RenderPasswordUpdated(ctx *fiber.Ctx) error {
	return ctx.Render("password-updated", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func RenderChangePassword(ctx *fiber.Ctx, errorMsg string) error {
	return ctx.Render("change-password", fiber.Map{
		"siteName":         ctx.Locals("siteName"),
		"csrfToken":        csrf.Get(sessions.Get(ctx)).Token,
		"turnstileSiteKey": ctx.Locals("turnstileSiteKey"),
		"errorMsg":         errorMsg,
	})
}

func RenderTOTPEnrollment(ctx *fiber.Ctx, data TOTPEnrollmentPageData) error {
	return ctx.Render("totp-enrollment", fiber.Map{
		"siteName":      ctx.Locals("siteName"),
		"csrfToken":     csrf.Get(sessions.Get(ctx)).Token,
		"secretKey":     data.SecretKey,
		"enrollmentURL": data.EnrollmentURL,
		"errorMsg":      data.ErrorMsg,
	})
}

func RenderTOTPEnrollSuccess(ctx *fiber.Ctx) error {
	return ctx.Render("totp-enroll-success", fiber.Map{
		"siteName": ctx.Locals("siteName"),
	})
}

func Render2FASettings(ctx *fiber.Ctx, data TwoFASettingsPageData) error {
	return ctx.Render("twofactor-settings", fiber.Map{
		"siteName":     ctx.Locals("siteName"),
		"csrfToken":    csrf.Get(sessions.Get(ctx)).Token,
		"email":        data.Email,
		"emailEnabled": data.EmailEnabled,
		"totpEnabled":  data.TOTPEnabled,
		"errorMsg":     data.ErrorMsg,
	})
}

func RenderVerifyTOTP(ctx *fiber.Ctx, errorMsg string) error {
	return ctx.Render("verify-totp", fiber.Map{
		"siteName":  ctx.Locals("siteName"),
		"csrfToken": csrf.Get(sessions.Get(ctx)).Token,
		"errorMsg":  errorMsg,
	})
}
