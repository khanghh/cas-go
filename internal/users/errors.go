package users

import "errors"

var (
	ErrUserNameExists  = errors.New("username already exists")
	ErrUserEmailExists = errors.New("email already exists")
)
