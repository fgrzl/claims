package jwtkit

import (
	"time"

	"github.com/fgrzl/claims"
)

type Validator interface {
	Validate(tokenStr string) (claims.Principal, error)
}

type Signer interface {
	CreateToken(principal claims.Principal, ttl time.Duration) (string, error)
}
