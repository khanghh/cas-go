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
	ErrSubjectMismatch        = errors.New("subject mismatch")
	ErrTokenInvalid           = errors.New("invalid token")
	ErrTokenExpired           = errors.New("token is expired")
	ErrOTPCodeExpired         = errors.New("OTP code is expired")
	ErrOTPRequestLimitReached = errors.New("OTP request limit reached")
	ErrOTPRequestRateLimited  = errors.New("otp request rate limited")
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

type AttemptFailError struct {
	AttemtpsLeft int
}

func (e *AttemptFailError) Error() string {
	return "verify attempt failed"
}

func NewAttemptFailError(attemtpsLeft int) *AttemptFailError {
	return &AttemptFailError{
		AttemtpsLeft: attemtpsLeft,
	}
}
