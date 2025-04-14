package middlewares

import "github.com/gofiber/fiber/v2"

type Middleware func(next fiber.Handler) fiber.Handler
