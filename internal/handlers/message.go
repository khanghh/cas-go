package handlers

import (
	"fmt"
	"math"
	"time"
)

const (
	MsgInvalidRequest           = "Invalid request. Please try again."
	MsgOTPCodeEmpty             = "OTP code cannot be empty."
	MsgInvalidOTP               = "Incorrect OTP. You have %d attempt(s) left."
	MsgTooManyOTPRequested      = "You've requested too many OTPs. Please try again later."
	MsgOTPRequestRateLimited    = "Please wait before requesting another OTP."
	MsgTooManyFailedAttempts    = "Too many failed attempts. Please try again later."
	MsgLoginSessionExpired      = "Session expired. Please log in again."
	MsgLoginWrongCredentials    = "Invalid username or password."
	ErrIncorrectPassword        = "Your current password is incorrect."
	MsgLoginEmailConflict       = "Email already linked to another account."
	MsgLoginUnsupportedOAuth    = "This OAuth provider is not supported."
	MsgTwoFactorChallengeFailed = "Two-factor authentication failed."
	MsgTwoFactorUserLocked      = "%s. Please try again in %s."
	MsgTooManyFailedLogin       = "Too many failed login attempts. Please try again later."
	MsgUserNotFound             = "No account found with that username and email address."
	MsgTOTPEnrollFailed         = "Verification failed. Please try again."
	MsgInvalid2FAMethod         = "The selected 2FA method is invalid or not supported."
	MsgInvalidCaptcha           = "Captcha verification failed."
)

func formatDuration(d time.Duration) string {
	plural := func(v int) string {
		if v == 1 {
			return ""
		}
		return "s"
	}

	d = time.Duration(math.Ceil(d.Seconds())) * time.Second
	if d < time.Minute {
		return "a minute"
	}

	minutes := int(math.Ceil(d.Minutes()))
	if d < time.Hour {
		if minutes == 1 {
			return "a minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}

	hours := int(d.Hours())
	mins := int(math.Ceil(d.Minutes())) % 60
	if d < 24*time.Hour {
		if mins == 0 {
			return fmt.Sprintf("%d hour%s", hours, plural(hours))
		}
		return fmt.Sprintf("%d hour%s %d minute%s", hours, plural(hours), mins, plural(mins))
	}

	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%d day%s", days, plural(days))
	}
	return fmt.Sprintf("%d day%s %d hour%s", days, plural(days), h, plural(h))
}
