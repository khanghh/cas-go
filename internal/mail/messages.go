package mail

import "fmt"

func SendOTP(sender MailSender, email string, otp string) error {
	return sender.Send(&Message{
		To:      []string{email},
		Subject: "OTP Verification",
		Body:    fmt.Sprintf("Your OTP is: %s", otp),
		IsHTML:  true,
	})
}
