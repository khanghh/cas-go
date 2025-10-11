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

func SendRegisterVerification(sender MailSender, email string, verifyURL string) error {
	params := fiber.Map{
		"verifyURL": verifyURL,
	}
	body, err := renderHTML("mail/confirm-register", params)
	if err != nil {
		return err
	}
	return sender.Send(&Message{
		To:      []string{email},
		Subject: "Please verify your email address",
		Body:    body,
		IsHTML:  true,
	})
}

func SendResetPasswordLink(sender MailSender, email string, resetLink string) error {
	params := fiber.Map{
		"resetLink":     resetLink,
		"expireMinutes": 5,
	}
	body, err := renderHTML("mail/reset-password", params)
	if err != nil {
		return err
	}
	return sender.Send(&Message{
		To:      []string{email},
		Subject: "Reset your password",
		Body:    body,
		IsHTML:  true,
	})
}
