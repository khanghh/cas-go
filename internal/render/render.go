package render

import (
	"github.com/gofiber/fiber/v2"
)

var globalVars fiber.Map

func Initialize(data fiber.Map) {
	globalVars = data
}

func RenderInternalServerError(ctx *fiber.Ctx) error {
	return ctx.Render("error-internal", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderNotFoundError(ctx *fiber.Ctx) error {
	return ctx.Render("error-not-found", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderForbiddenError(ctx *fiber.Ctx) error {
	return ctx.Render("error-forbidden", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderBadRequestError(ctx *fiber.Ctx) error {
	return ctx.Render("error-bad-request", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderLogin(ctx *fiber.Ctx, data LoginPageData) error {
	return ctx.Render("login", fiber.Map{
		"siteName":          globalVars["siteName"],
		"identifier":        data.Identifier,
		"googleOAuthURL":    data.OAuthLoginURLs["google"],
		"facebookOAuthURL":  data.OAuthLoginURLs["facebook"],
		"discordOAuthURL":   data.OAuthLoginURLs["discord"],
		"microsoftOAuthURL": data.OAuthLoginURLs["microsoft"],
		"appleOAuthURL":     data.OAuthLoginURLs["apple"],
		"csrfToken":         data.CSRFToken,
		"errorMsg":          data.ErrorMsg,
	})
}

func RenderRegister(ctx *fiber.Ctx, data RegisterPageData) error {
	return ctx.Render("register", fiber.Map{
		"siteName":      globalVars["siteName"],
		"username":      data.Username,
		"email":         data.Email,
		"csrfToken":     data.CSRFToken,
		"usernameError": data.FormErrors["username"],
		"passwordError": data.FormErrors["password"],
		"emailError":    data.FormErrors["email"],
		"errorMsg":      data.ErrorMsg,
	})
}

func RenderOAuthRegister(ctx *fiber.Ctx, data RegisterPageData) error {
	return ctx.Render("oauth-register", fiber.Map{
		"siteName":      globalVars["siteName"],
		"username":      data.Username,
		"fullName":      data.FullName,
		"email":         data.Email,
		"picture":       data.Picture,
		"oauthProvider": data.OAuthProvider,
		"csrfToken":     data.CSRFToken,
		"usernameError": data.FormErrors["username"],
		"passwordError": data.FormErrors["password"],
		"emailError":    data.FormErrors["email"],
		"errorMsg":      data.ErrorMsg,
	})
}

func RenderDeniedError(ctx *fiber.Ctx) error {
	return ctx.Render("error-denied", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderHomePage(ctx *fiber.Ctx, data HomePageData) error {
	displayName := data.FullName
	if displayName == "" {
		displayName = data.Username
	}
	return ctx.Render("home", fiber.Map{
		"siteName":    globalVars["siteName"],
		"displayName": displayName,
		"email":       data.Email,
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
		"siteName":     globalVars["siteName"],
		"challengeID":  data.ChallengeID,
		"emailEnabled": data.EmailEnabled,
		"smsEnabled":   data.SMSEnableled,
		"totpEnabled":  data.TOTPEnabled,
		"email":        email,
		"phone":        phone,
		"csrfToken":    data.CSRFToken,
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
		"siteName":     globalVars["siteName"],
		"emailOrPhone": emailOrPhone,
		"csrfToken":    pageData.CSRFToken,
		"errorMsg":     pageData.ErrorMsg,
	})
}

func RenderRegisterVerifyEmail(ctx *fiber.Ctx, email string) error {
	return ctx.Render("verify-email", fiber.Map{
		"siteName": globalVars["siteName"],
		"email":    email,
	})
}

func RenderEmailVerificationSuccess(ctx *fiber.Ctx, email string) error {
	return ctx.Render("verify-email-result", fiber.Map{
		"siteName": globalVars["siteName"],
		"success":  true,
		"email":    email,
	})
}

func RenderEmailVerificationFailure(ctx *fiber.Ctx) error {
	return ctx.Render("verify-email-result", fiber.Map{
		"siteName": globalVars["siteName"],
		"success":  false,
	})
}

func RenderAuthorizeServiceAccess(ctx *fiber.Ctx, data AuthorizeServicePageData) error {
	return ctx.Render("authorize-service", fiber.Map{
		"siteName":    globalVars["siteName"],
		"email":       data.Email,
		"serviceName": data.ServiceName,
		"serviceURL":  data.ServiceURL,
	})
}

func RenderForgotPassword(ctx *fiber.Ctx, sentEmail string) error {
	return ctx.Render("forgot-password", fiber.Map{
		"siteName":  globalVars["siteName"],
		"sentEmail": sentEmail,
		"csrfToken": globalVars["csrfToken"],
	})
}

func RenderSetNewPassword(ctx *fiber.Ctx, csrfToken string, errorMsg string) error {
	return ctx.Render("set-new-password", fiber.Map{
		"siteName":  globalVars["siteName"],
		"errorMsg":  errorMsg,
		"csrfToken": csrfToken,
	})
}

func RenderPasswordUpdated(ctx *fiber.Ctx) error {
	return ctx.Render("password-updated", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}
