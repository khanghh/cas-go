package handlers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/internal/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// GET /login?service=http%3A%2F%2Fwww.example.org
func (c *AuthHandler) GetLogin(ctx *fiber.Ctx) error {
	s := sessions.Get(ctx)
	if s.User == "" {
		fmt.Println("save")
		err := s.Save(sessions.SessionInfo{
			IP:        ctx.IP(),
			User:      "aaa",
			Email:     "aaa",
			LoginTime: time.Now(),
		})
		if err != nil {
			return err
		}
	}
	return ctx.SendString(s.User)
}

func (c *AuthHandler) PostLogin(ctx *fiber.Ctx) error {
	return nil
}

func (c *AuthHandler) PostLogout(ctx *fiber.Ctx) error {
	return nil
}

func (c *AuthHandler) PostCallback(ctx *fiber.Ctx) error {
	return nil
}
