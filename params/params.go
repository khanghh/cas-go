package params

import "time"

const (
	ServerBodyLimit               = 1048576 // 1 MiB
	ServerIdleTimeout             = 30 * time.Second
	ServerReadTimeout             = 10 * time.Second
	ServerWriteTimeout            = 10 * time.Second
	SessionStoreKeyPrefix         = "s:"
	TicketStoreKeyPrefix          = "t:"
	ChallengeStoreKeyPrefix       = "c:"
	UserStateStoreKeyPrefix       = "u:"
	PendingRegisterStoreKeyPrefix = "r:"
	PendingRegisterMaxAge         = 1 * time.Hour
	ServiceTicketExpiration       = 1 * time.Minute
	AuthStateTimeout              = 10 * time.Minute
	TwoFactorChallengeMaxAttempts = 5                // maximum number of attempts for a challenge
	TwoFactorUserMaxFailCount     = 10               // maximum number of fail attempts allowed per user, reset at challenge success
	TwoFactorUserMaxOTPRequests   = 20               // maximum number of OTP requests allowed per user
	TwoFactorUserMaxChallenges    = 20               // maximum number of challenges created per user
	TwoFactorUserStateMaxAge      = 12 * time.Hour   // time to live for a user state
	TwoFactorOTPExpiration        = 5 * time.Minute  // otp code expiration duration
	TwoFactorJWTExpiration        = 1 * time.Hour    // jwt token expiration duration
	TwoFactorValidityDuration     = 15 * time.Minute // validity duration for a 2FA login
)
