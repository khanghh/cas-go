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

func NewHtmlEngine(templateDir string) fiber.Views {
	if templateDir != "" {
		return html.NewFileSystem(http.Dir(templateDir), ".html")
	}
	renderFS, _ := fs.Sub(templateFS, "templates")
	return html.NewFileSystem(http.FS(renderFS), ".html")
}

func RenderLoginPage(ctx *fiber.Ctx, serviceUrl string, oauthLoginUrls map[string]string) error {
	return ctx.Render("login", fiber.Map{
		"serviceURL":            serviceUrl,
		"loginWithGoogleUrl":    oauthLoginUrls["google"],
		"loginWithFacebookUrl":  oauthLoginUrls["facebook"],
		"loginWithMicrosoftUrl": oauthLoginUrls["microsoft"],
		"loginWithAppleUrl":     oauthLoginUrls["apple"],
	})
}

func RenderUnauthorizedServiceErrorPage(ctx *fiber.Ctx, code int) error {
	return ctx.Render("unauthorized-service", fiber.Map{})
}
