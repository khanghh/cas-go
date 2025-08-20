package render

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

//go:embed templates/*.html
var templateFS embed.FS

var globalVars fiber.Map

func InitValues(data fiber.Map) {
	globalVars = data
}

func NewHtmlEngine(templateDir string) fiber.Views {
	if templateDir != "" {
		return html.NewFileSystem(http.Dir(templateDir), ".html")
	}
	renderFS, _ := fs.Sub(templateFS, "templates")
	return html.NewFileSystem(http.FS(renderFS), ".html")
}

func RenderLogin(ctx *fiber.Ctx, data LoginPageData) error {
	return ctx.Render("login", fiber.Map{
		"appName":           globalVars["appName"],
		"googleOAuthURL":    data.OAuthURLs["google"],
		"facebookOAuthURL":  data.OAuthURLs["facebook"],
		"discordOAuthURL":   data.OAuthURLs["discord"],
		"microsoftOAuthURL": data.OAuthURLs["microsoft"],
		"appleOAuthURL":     data.OAuthURLs["apple"],
		"identifier":        data.Identifier,
		"loginError":        data.LoginError,
	})
}

func RenderRegister(ctx *fiber.Ctx, data RegisterPageData) error {
	return ctx.Render("register", fiber.Map{
		"appName":       globalVars["appName"],
		"username":      data.Username,
		"email":         data.Email,
		"usernameError": data.UsernameError,
		"emailError":    data.EmailError,
		"passwordError": data.PasswordError,
	})
}

func RenderOnboarding(ctx *fiber.Ctx, data OnboardingPageData) error {
	return ctx.Render("onboarding", fiber.Map{
		"appName":       globalVars["appName"],
		"username":      data.Username,
		"fullName":      data.FullName,
		"email":         data.Email,
		"picture":       data.Picture,
		"usernameError": data.UsernameError,
		"passwordError": data.PasswordError,
		"emailError":    data.EmailError,
	})
}

func RenderUnauthorizedError(ctx *fiber.Ctx) error {
	return ctx.Render("unauthorized", fiber.Map{
		"appName": globalVars["appName"],
	})
}

func RenderInternalError(ctx *fiber.Ctx) error {
	return ctx.Render("internal-error", fiber.Map{
		"appName": globalVars["appName"],
	})
}
