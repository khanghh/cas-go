package mail

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/valyala/bytebufferpool"
)

var globalVars fiber.Map

var htmlEngine *html.Engine

func Initialize(engine *html.Engine, gVars fiber.Map) {
	htmlEngine = engine
	globalVars = gVars
}

func renderHTML(templateName string, vars fiber.Map) (string, error) {
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)
	err := htmlEngine.Render(buf, templateName, vars)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
