package twofactor

import (
	"errors"
	"time"
)

var (
	ErrChallengeNotFound      = errors.New("challenge not found")
	ErrChallengeInvalid       = errors.New("challenge invalid")
	ErrChallengeExpired       = errors.New("challenge expired")
	ErrTooManyAttemtps        = errors.New("too many attempts")
	ErrContextMismatch        = errors.New("context mismatch")
	ErrTokenInvalid           = errors.New("invalid token")
	ErrTokenExpired           = errors.New("token is expired")
	ErrOTPRequestLimitReached = errors.New("OTP request limit reached")
	ErrOTPCodeExpired         = errors.New("OTP code is expired")
)

type UserLockedError struct {
	Reason string
	Until  time.Time
}

func (e *UserLockedError) Error() string {
	return e.Reason
}

func NewUserLockedError(reason string, until time.Time) *UserLockedError {
	return &UserLockedError{
		Reason: reason,
		Until:  until,
	}
}

type VerifyFailError struct {
	AttemtpsLeft int
}

func (e *VerifyFailError) Error() string {
	return "verify attempt failed"
}

func NewVerifyFailError(attemtpsLeft int) *VerifyFailError {
	return &VerifyFailError{
		AttemtpsLeft: attemtpsLeft,
	}
}
