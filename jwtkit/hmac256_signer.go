package jwtkit

import (
	"time"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
)

// HMAC256Signer implements the Signer interface using HMAC-SHA256 signing.
type HMAC256Signer struct {
	Secret []byte
}

// CreateToken implements the Signer interface for HMAC256 signing.
func (tm *HMAC256Signer) CreateToken(principal claims.Principal, ttl time.Duration) (string, error) {
	mapClaims := ToMapClaims(principal, ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	return token.SignedString(tm.Secret)
}
