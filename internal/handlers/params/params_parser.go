package params

import (
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/cast"
)

func GetString(ctx *fiber.Ctx, name string) string {
	return ctx.Params(name)
}

func GetBool(ctx *fiber.Ctx, name string) bool {
	return cast.ToBool(ctx.Params(name))
}

func GetInt(ctx *fiber.Ctx, name string) int {
	return cast.ToInt(ctx.Params(name))
}

func GetInt32(ctx *fiber.Ctx, name string) int32 {
	return cast.ToInt32(ctx.Params(name))
}

func GetInt64(ctx *fiber.Ctx, name string) int64 {
	return cast.ToInt64(ctx.Params(name))
}
