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
	slog.Error("unhandled error", "code", code, "error", err)
	switch code {
	case fiber.StatusBadRequest:
		return render.RenderBadRequestError(ctx)
	case fiber.StatusForbidden:
		return render.RenderForbiddenError(ctx)
	case fiber.StatusNotFound:
		return render.RenderNotFoundError(ctx)
	default:
		return render.RenderInternalServerError(ctx)
	}
}
