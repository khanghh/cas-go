package params

import "time"

const (
	ServerBodyLimit               = 1048576 // 1 MiB
	ServerIdleTimeout             = 30 * time.Second
	ServerReadTimeout             = 10 * time.Second
	ServerWriteTimeout            = 10 * time.Second
	SessionKeyPrefix              = "s:"
	TicketKeyPrefix               = "t:"
	ChallengeKeyPrefix            = "c:"
	UserStateKeyPrefix            = "u:"
	PendingUserExpiration         = 1 * time.Hour
	ServiceTicketExpiration       = 1 * time.Minute
	TwoFactorChallengeMaxAttempts = 5               // maximum number of verification attempts allowed per challenge; reset with user state
	TwoFactorMaxFailCount         = 15              // maximum total failed verification attempts per user; resets on successful verification
	TwoFactorMaxOTPRequests       = 20              // maximum number of OTP code requests allowed per user; reset with user state
	TwoFactorMaxChallenges        = 10              // maximum number of pending challenges allowed per user; reset with user state
	TwoFactorChallengeCooldown    = 5 * time.Minute // cooldown duration for the challenge counter to reset
	TwoFactorOTPExpiration        = 5 * time.Minute // otp code expiration duration
	TwoFactorOTPRefreshCooldown   = 1 * time.Minute // otp code refresh cooldown
	TwoFactorStateMaxAge          = 24 * time.Hour  // time to live for user state
	TwoFactorJWTExpiration        = 1 * time.Hour   // jwt token expiration duration
	CSRFTokenExpiration           = 5 * time.Minute // csrf token expiration duration
)
