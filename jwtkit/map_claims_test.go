package jwtkit

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
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

func TestToMapClaims(t *testing.T) {
	tests := []struct {
		name        string
		setupClaims func() *claims.ClaimSet
		ttl         time.Duration
		expected    map[string]interface{}
	}{
		{
			name: "should convert basic claims",
			setupClaims: func() *claims.ClaimSet {
				return claims.NewClaimsSet("user123").
					SetIssuer("test-issuer").
					SetEmail("user@example.com")
			},
			ttl: 5 * time.Minute,
			expected: map[string]interface{}{
				"sub":   "user123",
				"iss":   "test-issuer",
				"email": "user@example.com",
			},
		},
		{
			name: "should convert timing claims as float64",
			setupClaims: func() *claims.ClaimSet {
				now := time.Now().Unix()
				return claims.NewClaimsSet("user123").
					SetExpiration(now + 3600).
					SetNotBefore(now - 300).
					SetIssuedAt(now)
			},
			ttl: 0, // No TTL injection
			expected: map[string]interface{}{
				"sub": "user123",
				"exp": float64(time.Now().Unix() + 3600),
				"nbf": float64(time.Now().Unix() - 300),
				"iat": float64(time.Now().Unix()),
			},
		},
		{
			name: "should convert array claims as slices",
			setupClaims: func() *claims.ClaimSet {
				return claims.NewClaimsSet("user123").
					SetRoles("admin", "user").
					SetScopes("read", "write", "delete")
			},
			ttl: 0,
			expected: map[string]interface{}{
				"sub":    "user123",
				"roles":  []string{"admin", "user"},
				"scopes": []string{"read", "write", "delete"},
			},
		},
		{
			name: "should inject expiration when TTL is positive and no exp exists",
			setupClaims: func() *claims.ClaimSet {
				return claims.NewClaimsSet("user123")
			},
			ttl: 10 * time.Minute,
			expected: map[string]interface{}{
				"sub": "user123",
				"exp": "INJECTED", // We'll verify this separately
			},
		},
		{
			name: "should not inject expiration when exp already exists",
			setupClaims: func() *claims.ClaimSet {
				existingExp := time.Now().Unix() + 1800
				return claims.NewClaimsSet("user123").SetExpiration(existingExp)
			},
			ttl: 10 * time.Minute,
			expected: map[string]interface{}{
				"sub": "user123",
				"exp": float64(time.Now().Unix() + 1800),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cs := tt.setupClaims()
			principal := claims.NewPrincipal(cs)

			// Act
			result := ToMapClaims(principal, tt.ttl)

			// Assert
			for key, expectedValue := range tt.expected {
				actualValue, exists := result[key]
				require.True(t, exists, "Expected key %s to exist in result", key)

				if key == "exp" && expectedValue == "INJECTED" {
					// Special case: verify exp was injected and is reasonable
					expValue, ok := actualValue.(float64)
					require.True(t, ok, "Expected exp to be float64")
					expectedExpRange := float64(time.Now().Add(tt.ttl).Unix())
					assert.InDelta(t, expectedExpRange, expValue, 2.0, "Expected exp to be close to now + TTL")
				} else if key == "exp" || key == "nbf" || key == "iat" {
					// Timing claims should be close to expected
					expectedFloat, ok := expectedValue.(float64)
					require.True(t, ok)
					actualFloat, ok := actualValue.(float64)
					require.True(t, ok)
					assert.InDelta(t, expectedFloat, actualFloat, 2.0, "Timing claim %s should be close to expected", key)
				} else {
					assert.Equal(t, expectedValue, actualValue, "Value for key %s should match", key)
				}
			}
		})
	}
}

func TestFromMapClaims(t *testing.T) {
	tests := []struct {
		name     string
		input    jwt.MapClaims
		expected map[string]string
	}{
		{
			name: "should convert string claims",
			input: jwt.MapClaims{
				"sub":   "user123",
				"iss":   "test-issuer",
				"email": "user@example.com",
			},
			expected: map[string]string{
				"sub":   "user123",
				"iss":   "test-issuer",
				"email": "user@example.com",
			},
		},
		{
			name: "should convert float64 claims to strings",
			input: jwt.MapClaims{
				"sub": "user123",
				"exp": float64(1640995200), // Use realistic Unix timestamps
				"nbf": float64(1640991600),
				"iat": float64(1640993400),
			},
			expected: map[string]string{
				"sub": "user123",
				"exp": "1.6409952e+09", // This is what fmt.Sprint actually produces
				"nbf": "1.6409916e+09",
				"iat": "1.6409934e+09",
			},
		},
		{
			name: "should convert array claims to comma-separated strings",
			input: jwt.MapClaims{
				"sub":    "user123",
				"roles":  []interface{}{"admin", "user"},
				"scopes": []interface{}{"read", "write", "delete"},
			},
			expected: map[string]string{
				"sub":    "user123",
				"roles":  "admin,user",
				"scopes": "read,write,delete",
			},
		},
		{
			name: "should convert mixed types to strings",
			input: jwt.MapClaims{
				"sub":      "user123",
				"age":      30,
				"height":   5.9,
				"active":   true,
				"metadata": map[string]interface{}{"key": "value"},
			},
			expected: map[string]string{
				"sub":      "user123",
				"age":      "30",
				"height":   "5.9",
				"active":   "true",
				"metadata": "map[key:value]",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			principal := FromMapClaims(tt.input)

			// Assert
			for key, expectedValue := range tt.expected {
				actualValue := principal.CustomClaimValue(key)
				assert.Equal(t, expectedValue, actualValue, "Value for key %s should match", key)
			}
		})
	}
}

func TestValidateStandardClaims(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name        string
		claims      jwt.MapClaims
		expectError bool
		errorText   string
	}{
		{
			name: "should pass with valid exp claim",
			claims: jwt.MapClaims{
				"exp": float64(now + 3600), // 1 hour in future
			},
			expectError: false,
		},
		{
			name: "should fail with expired token",
			claims: jwt.MapClaims{
				"exp": float64(now - 3600), // 1 hour in past
			},
			expectError: true,
			errorText:   "token has expired",
		},
		{
			name:        "should fail with missing exp claim",
			claims:      jwt.MapClaims{},
			expectError: true,
			errorText:   "expiration claim missing or invalid",
		},
		{
			name: "should fail with invalid exp claim type",
			claims: jwt.MapClaims{
				"exp": "not_a_number",
			},
			expectError: true,
			errorText:   "expiration claim missing or invalid",
		},
		{
			name: "should pass with valid nbf claim",
			claims: jwt.MapClaims{
				"exp": float64(now + 3600),
				"nbf": float64(now - 300), // 5 minutes ago
			},
			expectError: false,
		},
		{
			name: "should fail with future nbf claim",
			claims: jwt.MapClaims{
				"exp": float64(now + 3600),
				"nbf": float64(now + 300), // 5 minutes in future
			},
			expectError: true,
			errorText:   "token not valid yet",
		},
		{
			name: "should pass with valid iat claim",
			claims: jwt.MapClaims{
				"exp": float64(now + 3600),
				"iat": float64(now - 300), // 5 minutes ago
			},
			expectError: false,
		},
		{
			name: "should fail with future iat claim",
			claims: jwt.MapClaims{
				"exp": float64(now + 3600),
				"iat": float64(now + 300), // 5 minutes in future
			},
			expectError: true,
			errorText:   "token issued in the future",
		},
		{
			name: "should pass with all valid timing claims",
			claims: jwt.MapClaims{
				"exp": float64(now + 3600), // 1 hour in future
				"nbf": float64(now - 300),  // 5 minutes ago
				"iat": float64(now - 300),  // 5 minutes ago
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			err := ValidateStandardClaims(tt.claims)

			// Assert
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorText)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
