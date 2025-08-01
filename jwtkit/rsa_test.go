package jwtkit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fgrzl/claims"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTempRSAKeyFile(t *testing.T, isPrivate bool) string {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tempDir := t.TempDir()
	
	var keyBytes []byte
	var keyType string
	var filename string
	
	if isPrivate {
		keyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
		keyType = "RSA PRIVATE KEY"
		filename = "private.pem"
	} else {
		keyBytes = x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
		keyType = "RSA PUBLIC KEY"
		filename = "public.pem"
	}

	keyBlock := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}

	keyPath := filepath.Join(tempDir, filename)
	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	defer keyFile.Close()

	err = pem.Encode(keyFile, keyBlock)
	require.NoError(t, err)

	return keyPath
}

func TestLoadPrivateKey_ShouldLoadValidKey(t *testing.T) {
	// Arrange
	keyPath := createTempRSAKeyFile(t, true)

	// Act
	privateKey, err := LoadPrivateKey(keyPath)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, privateKey)
	assert.Equal(t, 2048, privateKey.N.BitLen())
}

func TestLoadPrivateKey_ShouldReturnErrorForNonExistentFile(t *testing.T) {
	// Arrange
	nonExistentPath := "/path/that/does/not/exist.pem"

	// Act
	privateKey, err := LoadPrivateKey(nonExistentPath)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, privateKey)
}

func TestLoadPrivateKey_ShouldReturnErrorForInvalidPEM(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	invalidKeyPath := filepath.Join(tempDir, "invalid.pem")
	err := os.WriteFile(invalidKeyPath, []byte("not a valid PEM file"), 0644)
	require.NoError(t, err)

	// Act
	privateKey, err := LoadPrivateKey(invalidKeyPath)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block found")
	assert.Nil(t, privateKey)
}

func TestLoadPublicKey_ShouldLoadValidKey(t *testing.T) {
	// Arrange
	keyPath := createTempRSAKeyFile(t, false)

	// Act
	publicKey, err := LoadPublicKey(keyPath)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, publicKey)
	assert.Equal(t, 2048, publicKey.N.BitLen())
}

func TestLoadPublicKey_ShouldReturnErrorForNonExistentFile(t *testing.T) {
	// Arrange
	nonExistentPath := "/path/that/does/not/exist.pem"

	// Act
	publicKey, err := LoadPublicKey(nonExistentPath)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, publicKey)
}

func TestLoadPublicKey_ShouldReturnErrorForInvalidPEM(t *testing.T) {
	// Arrange
	tempDir := t.TempDir()
	invalidKeyPath := filepath.Join(tempDir, "invalid.pem")
	err := os.WriteFile(invalidKeyPath, []byte("not a valid PEM file"), 0644)
	require.NoError(t, err)

	// Act
	publicKey, err := LoadPublicKey(invalidKeyPath)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block found")
	assert.Nil(t, publicKey)
}

func TestRSASigner_CreateToken_ShouldCreateValidToken(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	signer := &RSASigner{PrivateKey: privateKey}
	principal := claims.NewPrincipal(claims.NewClaimsSet("user123").SetIssuer("test-issuer"))

	// Act
	token, err := signer.CreateToken(principal, 5*time.Minute)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	
	// Verify the token can be validated
	validator := &RSAValidator{PublicKey: &privateKey.PublicKey}
	validatedPrincipal, err := validator.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, "user123", validatedPrincipal.Subject())
	assert.Equal(t, "test-issuer", validatedPrincipal.Issuer())
}

func TestRSAValidator_Validate_ShouldValidateValidToken(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	signer := &RSASigner{PrivateKey: privateKey}
	validator := &RSAValidator{PublicKey: &privateKey.PublicKey}
	
	principal := claims.NewPrincipal(
		claims.NewClaimsSet("user123").
			SetIssuer("test-issuer").
			SetEmail("user@example.com"),
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
}

func TestRSAValidator_Validate_ShouldRejectInvalidSignature(t *testing.T) {
	// Arrange
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	signer := &RSASigner{PrivateKey: privateKey1}
	validator := &RSAValidator{PublicKey: &privateKey2.PublicKey} // Different key
	
	principal := claims.NewPrincipal(claims.NewClaimsSet("user123"))
	token, err := signer.CreateToken(principal, 5*time.Minute)
	require.NoError(t, err)

	// Act
	validatedPrincipal, err := validator.Validate(token)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestRSAValidator_Validate_ShouldRejectMalformedToken(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validator := &RSAValidator{PublicKey: &privateKey.PublicKey}

	// Act
	validatedPrincipal, err := validator.Validate("invalid.token.format")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
}

func TestRSAValidator_Validate_ShouldRejectNonRSAToken(t *testing.T) {
	// Arrange
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	validator := &RSAValidator{PublicKey: &privateKey.PublicKey}
	
	// Create an HMAC token instead
	hmacSigner := &HMAC256Signer{Secret: []byte("secret")}
	principal := claims.NewPrincipal(claims.NewClaimsSet("user123"))
	hmacToken, err := hmacSigner.CreateToken(principal, 5*time.Minute)
	require.NoError(t, err)

	// Act
	validatedPrincipal, err := validator.Validate(hmacToken)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, validatedPrincipal)
	assert.Contains(t, err.Error(), "signature is invalid")
}