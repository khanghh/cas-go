package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/handler/params"
	"github.com/khanghh/cas-go/internal/render"
)

type AuthHandler struct {
	Services []string
}

func NewAuthHandler(servicesUrl []string) *AuthHandler {
	return &AuthHandler{}
}

func (c *AuthHandler) isServiceAllowed(s string) bool {
	for _, svc := range c.Services {
		if s == svc {
			return true
		}
	}
	return false
}

// GET /login?service=http%3A%2F%2Fwww.example.org
func (c *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	service := params.GetString(ctx, "service")
	// renew := params.GetBool(ctx, "renew")
	if service != "" && !c.isServiceAllowed(service) {
		return render.RenderUnauthorizedServiceErrorPage(ctx)
	}

	sid := ctx.Cookies("sid")
	if sid == "" {
		return render.RenderLoginPage(ctx)

	}
	return nil
}

func (c *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	return nil
}

func (c *AuthHandler) PostCallback(ctx *fiber.Ctx) error {
	return nil
}
