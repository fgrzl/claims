package jwtkit

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
)

// RSAValidator implements the Validator interface using RSA public key validation.
type RSAValidator struct {
	PublicKey *rsa.PublicKey
}

// LoadPublicKey loads an RSA public key from a PEM file.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// Validate implements the Validator interface for RSA validation.
func (v *RSAValidator) Validate(tokenStr string) (claims.Principal, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return v.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	if err := ValidateStandardClaims(claims); err != nil {
		return nil, err
	}

	return FromMapClaims(claims), nil
}
