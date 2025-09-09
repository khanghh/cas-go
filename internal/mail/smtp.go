package mail

import "gopkg.in/gomail.v2"

type SMTPMailSender struct {
	*gomail.Dialer
	From string
}

func (s *SMTPMailSender) Send(message *Message) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", s.From)
	msg.SetHeader("To", message.To...)
	msg.SetHeader("Cc", message.Cc...)
	msg.SetHeader("Subject", message.Subject)
	if message.IsHTML {
		msg.SetBody("text/html", message.Body)
	} else {
		msg.SetBody("text/plain", message.Body)
	}
	msg.SetBody("text/html", message.Body)
	for cid, file := range message.Embeds {
		msg.Embed(file, gomail.SetHeader(map[string][]string{
			"Content-ID": {"<" + cid + ">"},
		}))
	}
	for _, file := range message.Attachments {
		msg.Attach(file)
	}
	return s.DialAndSend(msg)
}

func NewSMTPMailSender(dialer *gomail.Dialer, from string) MailSender {
	return &SMTPMailSender{
		Dialer: dialer,
		From:   from,
	}
}
