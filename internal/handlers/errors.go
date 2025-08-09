package handlers

import "errors"

var (
	ErrLoginInvalidCredentials = errors.New("invalid username or password")
	ErrLoginUserDisabled       = errors.New("account is disabled")
	ErrLoginTooManyAttempts    = errors.New("too many login attempts, please try again later")
	ErrLoginEmailNotVerified   = errors.New("please verify your email before logging in")
	ErrLoginMissingFields      = errors.New("username and password are required")
)
