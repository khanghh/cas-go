package users

import (
	"errors"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrUsernameTaken            = errors.New("username taken")
	ErrEmailRegisterd           = errors.New("email already registered")
	ErrPendingUserNotFound      = errors.New("pending registration user not found")
	ErrInvalidVerificationToken = errors.New("invalid verification token")
)
