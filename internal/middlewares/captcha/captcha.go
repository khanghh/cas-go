package captcha

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

var (
	ErrInvalidCaptcha = errors.New("invalid captcha")
)

type CaptchaVerifier interface {
	Verify(ctx *fiber.Ctx) error
}

var verifier CaptchaVerifier

func InitVerifier(v CaptchaVerifier) {
	verifier = v
}

func Verify(ctx *fiber.Ctx) error {
	return verifier.Verify(ctx)
}

type CaptchaError struct {
	message string
}

func (e *CaptchaError) Error() string {
	return e.message
}

func (e *CaptchaError) Is(target error) bool {
	_, ok := target.(*CaptchaError)
	return ok
}

func newCaptchaError(message string) *CaptchaError {
	return &CaptchaError{message: message}
}

type NullVerifier struct{}

func (v *NullVerifier) Verify(ctx *fiber.Ctx) error {
	return nil
}

func NewNullVerifier() *NullVerifier {
	return &NullVerifier{}
}
