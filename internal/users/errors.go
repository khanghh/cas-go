package users

import (
	"errors"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserNameExists    = errors.New("username already exists")
	ErrUserEmailExists   = errors.New("email already exists")
	ErrPendingUserExists = errors.New("a pending registration already exists for this user")
)
