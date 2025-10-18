package twofactor

import (
	"errors"
	"time"
)

var (
	ErrChallengeNotFound            = errors.New("challenge not found")
	ErrChallengeInvalid             = errors.New("challenge invalid")
	ErrChallengeExpired             = errors.New("challenge expired")
	ErrChallengeAttemptsExceeded    = errors.New("max challenge attempts exceeded")
	ErrChallengeAlreadyVerified     = errors.New("challenge already verified")
	ErrChallengeNotVerified         = errors.New("challenge not verified")
	ErrChallengeSubjectMismatch     = errors.New("challenge subject mismatch")
	ErrChallengeTypeMismatch        = errors.New("challenge type mismatch")
	ErrChallengeCallbackURLMismatch = errors.New("challenge callback url mismatch")
	ErrInvalidFinalizeToken         = errors.New("invalid finalize token")
	ErrTooManyFailedAttempts        = errors.New("too many failed attempts")
	ErrUserChallengeRateLimited     = errors.New("request rate limited")
	ErrTokenInvalid                 = errors.New("invalid token")
	ErrTokenExpired                 = errors.New("token is expired")
	ErrOTPCodeExpired               = errors.New("OTP code is expired")
	ErrOTPRequestLimitReached       = errors.New("OTP request limit reached")
	ErrOTPRequestRateLimited        = errors.New("otp request rate limited")
	ErrTOTPNotEnrolled              = errors.New("TOTP not enrolled")
	ErrTOTPVerifyFailed             = errors.New("TOTP verification failed")
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
	AttemptsLeft int
}

func (e *AttemptFailError) Error() string {
	return "verify attempt failed"
}

func NewAttemptFailError(attemptsLeft int) *AttemptFailError {
	return &AttemptFailError{
		AttemptsLeft: attemptsLeft,
	}
}
