package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
)

func redirect(ctx *fiber.Ctx, location string, params fiber.Map) error {
	url, err := url.Parse(location)
	if err != nil {
		return err
	}
	query := url.Query()
	for key, value := range params {
		if value != nil && value != "" {
			query.Set(key, fmt.Sprintf("%v", value))
		}
	}
	url.RawQuery = query.Encode()
	return ctx.Redirect(url.String())
}

func redirectInternal(ctx *fiber.Ctx, location string) error {
	ctx.Path(location)
	ctx.Method(http.MethodGet)
	return ctx.RestartRouting()
}

func performLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return redirect(ctx, "/login", nil)
}
