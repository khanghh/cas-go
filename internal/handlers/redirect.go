package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
)

func redirect(ctx *fiber.Ctx, location string, pairs ...any) error {
	url, err := url.Parse(location)
	if err != nil {
		return err
	}

	query := url.Query()
	for i := 0; i < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		if !ok {
			return fmt.Errorf("key at position %d is not a string", i)
		}
		query.Set(key, fmt.Sprint(pairs[i+1]))
	}

	url.RawQuery = query.Encode()
	return ctx.Redirect(url.String())
}

func redirectInternal(ctx *fiber.Ctx, location string) error {
	ctx.Path(location)
	ctx.Method(http.MethodGet)
	return ctx.RestartRouting()
}

func forceLogout(ctx *fiber.Ctx) error {
	sessions.Destroy(ctx)
	return redirect(ctx, "/login", nil)
}
