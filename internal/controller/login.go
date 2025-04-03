package controller

import (
	"github.com/gofiber/fiber/v2"
)

type AuthController struct {
}

func NewAuthController() *AuthController {
	return &AuthController{}
}

func (c *AuthController) GetLoginHandler(ctx *fiber.Ctx) error {
	return ctx.Render("login", fiber.Map{
		"Title": "Welcome to My App",
	})
}

func (c *AuthController) PostLogoutHandler(ctx *fiber.Ctx) error {
	return nil
}
