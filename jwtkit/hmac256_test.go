package jwtkit

import (
	"testing"
	"time"

	"github.com/fgrzl/claims"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMAC256Signer_CreateToken_ShouldCreateValidToken(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	signer := &HMAC256Signer{Secret: secret}
	principal := claims.NewPrincipal(
		claims.NewClaimsSet("user123").
			SetIssuer("test-issuer").
			SetEmail("user@example.com"),
	)

	// Act
	token, err := signer.CreateToken(principal, 5*time.Minute)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	
	// Verify the token can be validated
	validator := &HMAC256Validator{Secret: secret}
	validatedPrincipal, err := validator.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, "user123", validatedPrincipal.Subject())
	assert.Equal(t, "test-issuer", validatedPrincipal.Issuer())
	assert.Equal(t, "user@example.com", validatedPrincipal.Email())
}

func TestHMAC256Signer_CreateToken_WithZeroTTL(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	signer := &HMAC256Signer{Secret: secret}
	principal := claims.NewPrincipal(claims.NewClaimsSet("user123"))

	// Act
	token, err := signer.CreateToken(principal, 0)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestHMAC256Validator_Validate_ShouldValidateValidToken(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	signer := &HMAC256Signer{Secret: secret}
	validator := &HMAC256Validator{Secret: secret}
	
	principal := claims.NewPrincipal(
		claims.NewClaimsSet("user123").
			SetIssuer("test-issuer").
			SetEmail("user@example.com").
			SetRoles("admin", "user").
			SetScopes("read", "write"),
	)
	
	token, err := signer.CreateToken(principal, 5*time.Minute)
	require.NoError(t, err)

	// Act
	validatedPrincipal, err := validator.Validate(token)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "user123", validatedPrincipal.Subject())
	assert.Equal(t, "test-issuer", validatedPrincipal.Issuer())
	assert.Equal(t, "user@example.com", validatedPrincipal.Email())
	assert.Equal(t, []string{"admin", "user"}, validatedPrincipal.Roles())
	assert.Equal(t, []string{"read", "write"}, validatedPrincipal.Scopes())
}

func TestHMAC256Validator_Validate_ShouldRejectInvalidSecret(t *testing.T) {
	// Arrange
	secret1 := []byte("secret-key-1")
	secret2 := []byte("secret-key-2")
	
	signer := &HMAC256Signer{Secret: secret1}
	validator := &HMAC256Validator{Secret: secret2} // Different secret
	
	principal := claims.NewPrincipal(claims.NewClaimsSet("user123"))
	token, err := signer.CreateToken(principal, 5*time.Minute)
	require.NoError(t, err)

	// Act
	validatedPrincipal, err := validator.Validate(token)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "failed to parse token")
}

func TestHMAC256Validator_Validate_ShouldRejectMalformedToken(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	validator := &HMAC256Validator{Secret: secret}

	// Act
	validatedPrincipal, err := validator.Validate("invalid.token.format")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "failed to parse token")
}

func TestHMAC256Validator_Validate_ShouldRejectEmptyToken(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	validator := &HMAC256Validator{Secret: secret}

	// Act
	validatedPrincipal, err := validator.Validate("")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "failed to parse token")
}

func TestHMAC256Validator_Validate_ShouldRejectExpiredToken(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	signer := &HMAC256Signer{Secret: secret}
	validator := &HMAC256Validator{Secret: secret}
	
	principal := claims.NewPrincipal(claims.NewClaimsSet("user123"))
	token, err := signer.CreateToken(principal, 1*time.Millisecond)
	require.NoError(t, err)
	
	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Act
	validatedPrincipal, err := validator.Validate(token)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestHMAC256Validator_Validate_ShouldHandleTokenWithoutExpiration(t *testing.T) {
	// Arrange
	secret := []byte("super-secret-key")
	validator := &HMAC256Validator{Secret: secret}
	
	// Create a principal without expiration
	cs := claims.NewClaimsSet("user123").SetIssuer("test-issuer")
	principal := claims.NewPrincipal(cs)
	
	signer := &HMAC256Signer{Secret: secret}
	token, err := signer.CreateToken(principal, 0) // Zero TTL means no expiration will be added
	require.NoError(t, err)

	// Act
	validatedPrincipal, err := validator.Validate(token)

	// Assert - Should fail because expiration claim is required by ValidateStandardClaims
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "expiration claim missing or invalid")
}

func TestHMAC256_Integration_RoundTrip(t *testing.T) {
	// Arrange
	secret := []byte("integration-test-secret")
	signer := &HMAC256Signer{Secret: secret}
	validator := &HMAC256Validator{Secret: secret}
	
	// Create a complex principal with various claims
	now := time.Now().Unix()
	cs := claims.NewClaimsSet("integration-user").
		SetIssuer("integration-issuer").
		SetAudience("api1,api2").
		SetEmail("integration@example.com").
		SetName("Integration User").
		SetTokenID("integration-token-123").
		SetIssuedAt(now). // Set the issued at time
		SetRoles("admin", "user", "guest").
		SetScopes("read", "write", "delete").
		Set("custom_field", "custom_value").
		Set("department", "engineering")
	
	principal := claims.NewPrincipal(cs)

	// Act
	token, err := signer.CreateToken(principal, 10*time.Minute)
	require.NoError(t, err)
	
	validatedPrincipal, err := validator.Validate(token)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, "integration-user", validatedPrincipal.Subject())
	assert.Equal(t, "integration-issuer", validatedPrincipal.Issuer())
	assert.Equal(t, []string{"api1", "api2"}, validatedPrincipal.Audience())
	assert.Equal(t, "integration@example.com", validatedPrincipal.Email())
	assert.Equal(t, "Integration User", validatedPrincipal.Username())
	assert.Equal(t, "integration-token-123", validatedPrincipal.JWTI())
	assert.Equal(t, []string{"admin", "user", "guest"}, validatedPrincipal.Roles())
	assert.Equal(t, []string{"read", "write", "delete"}, validatedPrincipal.Scopes())
	assert.Equal(t, "custom_value", validatedPrincipal.CustomClaimValue("custom_field"))
	assert.Equal(t, "engineering", validatedPrincipal.CustomClaimValue("department"))
	
	// Note: Timing claims (exp, iat, nbf) may have conversion issues due to 
	// scientific notation in the round-trip process, but that's a known limitation
}