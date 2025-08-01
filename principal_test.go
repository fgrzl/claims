package claims

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldCreatePrincipalFromListWhenGiven(t *testing.T) {
	// Arrange
	claimsList := NewClaimsList("sub", "user123").Add("email", "user@example.com")

	// Act
	p := NewPrincipalFromList(claimsList)

	// Assert
	assert.Equal(t, "user123", p.Subject())
	assert.Equal(t, "user@example.com", p.Email())
}

func TestShouldAccessClaimsWhenUsingPrincipal(t *testing.T) {
	// Arrange
	now := time.Now().Unix()
	cs := NewClaimsSet("abc123").
		Set("exp", strconv.FormatInt(now+3600, 10)).
		Set("aud", "api1,api2").
		Set("scopes", "read,write")

	// Act
	p := NewPrincipal(cs)

	// Assert
	assert.Equal(t, "abc123", p.Subject())
	assert.ElementsMatch(t, []string{"api1", "api2"}, p.Audience())
	assert.ElementsMatch(t, []string{"read", "write"}, p.Scopes())
	assert.Equal(t, now+3600, p.ExpirationTime())
}

func TestShouldReturnCustomClaimFromPrincipalWhenExists(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("tester").Set("foo", "bar")
	p := NewPrincipal(cs)

	// Act
	claim := p.CustomClaim("foo")
	val := p.CustomClaimValue("foo")
	missing := p.CustomClaim("missing")

	// Assert
	assert.Equal(t, "bar", claim.Value())
	assert.Equal(t, "bar", val)
	assert.Equal(t, "", missing.Value())
}

func TestShouldReturnClaimsCopyWhenRequested(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("copyme")
	p := NewPrincipal(cs)

	// Act
	claimsMap := p.Claims()
	claimsMap.SetSubject("tampered")

	// Assert
	// Original Principal should not be affected
	assert.Equal(t, "copyme", p.Subject())
}
