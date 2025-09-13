package mail

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

func SendOTP(sender MailSender, email string, otpCode string) error {
	params := fiber.Map{
		"otpCode":       otpCode,
		"expireMinutes": 5,
	}
	body, err := renderHTML("mail/otp-code", params)
	if err != nil {
		return err
	}
	return sender.Send(&Message{
		To:      []string{email},
		Subject: fmt.Sprintf("%s is your verification code", otpCode),
		Body:    body,
		IsHTML:  true,
	})
}
