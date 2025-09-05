package params

import "time"

const (
	ServerBodyLimit               = 1048576
	ServerIdleTimeout             = 30 * time.Second
	ServerReadTimeout             = 10 * time.Second
	ServerWriteTimeout            = 10 * time.Second
	TicketStorageKeyPrefix        = "t:"
	SessionStorageKeyPrefix       = "s:"
	ChallengeStorageKeyPrefix     = "c:"
	ServiceTicketExpiration       = 1 * time.Minute
	AuthStateTimeout              = 10 * time.Minute
	TwoFactorChallengeMaxAttempts = 5 // maximum number of attempts for a challenge

	TwoFactorUserMaxFailChallenges = 5 // maximum number of failed challenges
)
