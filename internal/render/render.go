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
		"siteName":          globalVars["siteName"],
		"identifier":        data.Identifier,
		"loginError":        data.LoginError,
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
		"usernameError": data.FormErrors["username"],
		"passwordError": data.FormErrors["password"],
		"emailError":    data.FormErrors["email"],
	})
}

func RenderUnauthorizedError(ctx *fiber.Ctx) error {
	return ctx.Render("unauthorized", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderInternalError(ctx *fiber.Ctx) error {
	return ctx.Render("internal-error", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}

func RenderHomePage(ctx *fiber.Ctx) error {
	return ctx.Render("home", fiber.Map{
		"siteName": globalVars["siteName"],
	})
}
