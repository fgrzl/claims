package jwtkit

import (
	"time"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
)

type HMAC256Signer struct {
	Secret []byte
}

func (tm *HMAC256Signer) CreateToken(principal claims.Principal, ttl time.Duration) (string, error) {
	mapClaims := ToMapClaims(principal, ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	return token.SignedString(tm.Secret)
}
