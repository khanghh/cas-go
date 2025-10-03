package users

import (
	"errors"
)

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrUsernameTaken       = errors.New("username already exists")
	ErrEmailRegisterd      = errors.New("email already registered")
	ErrPendingUserNotFound = errors.New("pending user not found")
)
