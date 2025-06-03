package jwtkit

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type signerValidatorPair struct {
	name          string
	signer        Signer
	validator     Validator
	mismatchedSig func() Validator
}

func generateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func TestJWTSignerBehavior(t *testing.T) {
	secret := []byte("super-secret-key")
	rsaPriv1, rsaPub1 := generateRSAKeyPair(t)
	_, rsaPub2 := generateRSAKeyPair(t)

	cases := []signerValidatorPair{
		{
			name:      "using HMAC signer and validator",
			signer:    &HMAC256Signer{Secret: secret},
			validator: &HMAC256Validator{Secret: secret},
			mismatchedSig: func() Validator {
				return &HMAC256Validator{Secret: []byte("wrong-secret")}
			},
		},
		{
			name:      "using RSA signer and validator",
			signer:    &RSASigner{PrivateKey: rsaPriv1},
			validator: &RSAValidator{PublicKey: rsaPub1},
			mismatchedSig: func() Validator {
				return &RSAValidator{PublicKey: rsaPub2}
			},
		},
	}

	for _, tc := range cases {
		t.Run("should create and validate a token "+tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"tenant_id": "tenant-xyz"}
			token, err := tc.signer.CreateToken(FromMapClaims(claims), time.Minute)
			require.NoError(t, err)

			user, err := tc.validator.Validate(token)
			require.NoError(t, err)
			require.Equal(t, "tenant-xyz", user.CustomClaimValue("tenant_id"))
		})

		t.Run("should reject expired tokens "+tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"tenant_id": "expired"}
			token, err := tc.signer.CreateToken(FromMapClaims(claims), 1*time.Second)
			require.NoError(t, err)

			time.Sleep(2 * time.Second)

			_, err = tc.validator.Validate(token)
			require.Error(t, err)
			require.ErrorContains(t, err, "token is expired")
		})

		t.Run("should reject tokens with invalid signature "+tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"tenant_id": "bad-sig"}
			token, err := tc.signer.CreateToken(FromMapClaims(claims), time.Minute)
			require.NoError(t, err)

			_, err = tc.mismatchedSig().Validate(token)
			require.Error(t, err)
			require.ErrorContains(t, err, "signature is invalid")
		})
	}
}

var testSigningKey = []byte("test-secret")
