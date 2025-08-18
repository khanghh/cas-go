package handlers

import (
	"errors"
	"net/mail"
	"net/url"
	"regexp"

	"github.com/khanghh/cas-go/internal/render"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

func validateUsername(username string) error {
	if username == "" {
		return errors.New("Username is required.")
	}
	if len(username) < 4 {
		return errors.New("Username must be at least 4 characters.")
	}
	if len(username) > 32 {
		return errors.New("Username must be less than 32 characters.")
	}
	if !usernameRegex.MatchString(username) {
		return errors.New("Username can only contain letters, numbers, and underscores.")
	}
	return nil
}

func validateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("Invalid email address.")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 6 {
		return errors.New("Password must be at least 6 characters.")
	}
	return nil
}

func validateOnboardingForm(form *render.OnboardingForm) error {
	if err := validateUsername(form.Username); err != nil {
		form.UsernameError = err.Error()
		return err
	}

	if err := validatePassword(form.Password); err != nil {
		form.PasswordError = err.Error()
		return err
	}

	if err := validateEmail(form.Email); err != nil {
		form.EmailError = err.Error()
		return err
	}
	return nil
}

// parseServiceURL parses the service URL and returns the base URL without query
func parseServiceURL(serviceURL string) (string, error) {
	parsed, err := url.Parse(serviceURL)
	if err != nil {
		return "", err
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String(), nil
}
