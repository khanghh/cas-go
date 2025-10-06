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
		"loginError":        data.ErrorMsg,
		"googleOAuthURL":    data.OAuthLoginURLs["google"],
		"facebookOAuthURL":  data.OAuthLoginURLs["facebook"],
		"discordOAuthURL":   data.OAuthLoginURLs["discord"],
		"microsoftOAuthURL": data.OAuthLoginURLs["microsoft"],
		"appleOAuthURL":     data.OAuthLoginURLs["apple"],
	})
}

func RenderRegister(ctx *fiber.Ctx, data RegisterPageData) error {
	return ctx.Render("register", fiber.Map{
		"siteName":      globalVars["siteName"],
		"username":      data.Username,
		"email":         data.Email,
		"usernameError": data.FormErrors["username"],
		"passwordError": data.FormErrors["password"],
		"emailError":    data.FormErrors["email"],
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
		"usernameError": data.FormErrors["username"],
		"passwordError": data.FormErrors["password"],
		"emailError":    data.FormErrors["email"],
	})
}

func RenderDeniedError(ctx *fiber.Ctx) error {
	return ctx.Render("error-denied", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderHomePage(ctx *fiber.Ctx, pageData HomePageData) error {
	displayName := pageData.FullName
	if displayName == "" {
		displayName = pageData.Username
	}
	return ctx.Render("home", fiber.Map{
		"siteName":    globalVars["siteName"],
		"displayName": displayName,
		"email":       pageData.Email,
	})
}

func RenderVerificationRequired(ctx *fiber.Ctx, pageData VerificationRequiredPageData) error {
	email := pageData.Email
	phone := formatPhone(pageData.Phone)
	if pageData.IsMasked {
		email = maskEmail(email)
		phone = maskPhone(phone)
	}
	return ctx.Render("verification-required", fiber.Map{
		"siteName":     globalVars["siteName"],
		"challengeID":  pageData.ChallengeID,
		"emailEnabled": pageData.EmailEnabled,
		"smsEnabled":   pageData.SMSEnableled,
		"totpEnabled":  pageData.TOTPEnabled,
		"email":        email,
		"phone":        phone,
		"methodError":  pageData.MethodError,
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
		"verifyError":  pageData.VerifyError,
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
