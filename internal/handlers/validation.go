package handlers

import (
	"errors"
	"net/mail"
	"net/url"
	"regexp"
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
	if first := username[0]; !(('A' <= first && first <= 'Z') || ('a' <= first && first <= 'z')) {
		return errors.New("Username must start with a letter.")
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
