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
	AuthStateTimeout              = 10 * time.Minute
	TwoFactorChallengeMaxAttempts = 5                  // maximum number of attempts for a challenge
	TwoFactorMaxFailCount         = 10                 // maximum number of fail attempts allowed per user, reset at challenge success
	TwoFactorMaxOTPRequests       = 20                 // maximum number of OTP requests allowed per user
	TwoFactorMaxChallenges        = 20                 // maximum number of challenges created per user
	TwoFactorStateMaxAge          = 12 * time.Hour     // time to live for a user state
	TwoFactorOTPExpiration        = 5 * time.Minute    // otp code expiration duration
	TwoFactorOTPRefreshCooldown   = 1 * time.Minute    // otp code refresh cooldown
	TwoFactorJWTExpiration        = 1 * time.Hour      // jwt token expiration duration
	TrustedDeviceExpiration       = 7 * 24 * time.Hour // trusted device expiration duration
	CSRFTokenExpiration           = 5 * time.Minute
)
