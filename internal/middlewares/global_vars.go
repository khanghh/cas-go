package middlewares

import "github.com/gofiber/fiber/v2"

func GlobalVars(vars fiber.Map) fiber.Handler {
	return func(c *fiber.Ctx) error {
		for key, val := range vars {
			c.Locals(key, val)
		}
		return c.Next()
	}
}
