package jwtkit

import (
	"time"

	"github.com/fgrzl/claims"
)

// Validator defines the interface for validating JWT tokens and extracting principals.
type Validator interface {
	Validate(tokenStr string) (claims.Principal, error)
}

// Signer defines the interface for creating JWT tokens from principals.
type Signer interface {
	CreateToken(principal claims.Principal, ttl time.Duration) (string, error)
}
