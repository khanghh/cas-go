package middlewares

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/render"
)

func ErrorHandler(ctx *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	switch code {
	case fiber.StatusBadRequest:
		return render.RenderBadRequestError(ctx)
	case fiber.StatusForbidden:
		return render.RenderForbiddenError(ctx)
	case fiber.StatusNotFound, fiber.StatusMethodNotAllowed:
		return render.RenderNotFoundError(ctx)
	default:
		slog.Error("unhandled error", "path", ctx.Path(), "code", code, "error", err)
		return render.RenderInternalServerError(ctx)
	}
}
