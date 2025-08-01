package jwtkit

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
)

// LoadPrivateKey loads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// RSASigner implements the Signer interface using RSA-SHA256 signing.
type RSASigner struct {
	PrivateKey *rsa.PrivateKey
}

// CreateToken implements the Signer interface for RSA signing.
func (s *RSASigner) CreateToken(principal claims.Principal, ttl time.Duration) (string, error) {
	mapClaims := ToMapClaims(principal, ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	return token.SignedString(s.PrivateKey)
}
