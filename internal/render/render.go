package render

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/khanghh/cas-go/model"
)

//go:embed templates/*.html
var templateFS embed.FS

var values fiber.Map

func InitValues(data fiber.Map) {
	values = data
}

func NewHtmlEngine(templateDir string) fiber.Views {
	if templateDir != "" {
		return html.NewFileSystem(http.Dir(templateDir), ".html")
	}
	renderFS, _ := fs.Sub(templateFS, "templates")
	return html.NewFileSystem(http.FS(renderFS), ".html")
}

func RenderLoginPage(ctx *fiber.Ctx, serviceURL string, oauthLoginURLs map[string]string) error {
	return ctx.Render("login", fiber.Map{
		"appName":               values["appName"],
		"serviceURL":            serviceURL,
		"loginWithGoogleURL":    oauthLoginURLs["google"],
		"loginWithFacebookURL":  oauthLoginURLs["facebook"],
		"loginWithMicrosoftURL": oauthLoginURLs["microsoft"],
		"loginWithAppleURL":     oauthLoginURLs["apple"],
	})
}

func RenderRegisterPage(ctx *fiber.Ctx) error {
	return ctx.Render("register", fiber.Map{
		"appName": values["appName"],
	})
}

func RenderOAuthRegisterPage(ctx *fiber.Ctx, userOAuth *model.UserOAuth) error {
	return ctx.Render("oauth_register", fiber.Map{
		"appName":           values["appName"],
		"fullName":          userOAuth.Name,
		"email":             userOAuth.Email,
		"provider":          userOAuth.Provider,
		"picture":           userOAuth.Picture,
		"suggestedUsername": "aaa",
	})
}

func RenderUnauthorizedErrorPage(ctx *fiber.Ctx, code int) error {
	return ctx.Render("unauthorized-service", fiber.Map{})
}
