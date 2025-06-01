package auth

import "errors"

var (
	ErrTicketExpired           = errors.New("ticket expired")
	ErrTicketNotFound          = errors.New("ticket not found")
	ErrServiceUrlMismatch      = errors.New("service url mismatch")
	ErrServiceNotFound         = errors.New("service not found")
	ErrInvalidSignature        = errors.New("invalid signature")
	ErrInvalidServicePublicKey = errors.New("invalid service public key")
)
