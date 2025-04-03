package params

import "time"

const (
	ServerBodyLimit    = 1048576
	ServerIdleTimeout  = 30 * time.Second
	ServerReadTimeout  = 10 * time.Second
	ServerWriteTimeout = 10 * time.Second
)
