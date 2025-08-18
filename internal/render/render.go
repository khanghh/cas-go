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

func RenderLogin(ctx *fiber.Ctx, serviceURL string, oauthURLs map[string]string) error {
	return ctx.Render("login", fiber.Map{
		"appName":           values["appName"],
		"serviceURL":        serviceURL,
		"googleOAuthURL":    oauthURLs["google"],
		"facebookOAuthURL":  oauthURLs["facebook"],
		"discordOAuthURL":   oauthURLs["discord"],
		"microsoftOAuthURL": oauthURLs["microsoft"],
		"appleOAuthURL":     oauthURLs["apple"],
	})
}

func RenderRegister(ctx *fiber.Ctx) error {
	return ctx.Render("register", fiber.Map{
		"appName": values["appName"],
	})
}

type OnboardingForm struct {
	Username      string `form:"username"`
	Password      string `form:"password"`
	Email         string `form:"email"`
	FullName      string `form:"fullName"`
	Picture       string `form:"picture"`
	UsernameError string
	PasswordError string
	EmailError    string
}

func RenderOnboarding(ctx *fiber.Ctx, form OnboardingForm) error {
	return ctx.Render("onboarding", fiber.Map{
		"appName":       values["appName"],
		"username":      form.Username,
		"fullName":      form.FullName,
		"email":         form.Email,
		"picture":       form.Picture,
		"usernameError": form.UsernameError,
		"passwordError": form.PasswordError,
		"emailError":    form.EmailError,
	})
}

func RenderUnauthorizedError(ctx *fiber.Ctx) error {
	return ctx.Render("unauthorized", fiber.Map{
		"appName": values["appName"],
	})
}

func RenderInternalError(ctx *fiber.Ctx) error {
	return ctx.Render("internal-error", fiber.Map{
		"appName": values["appName"],
	})
}
