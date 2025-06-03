package claims

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewPrincipalFromList(t *testing.T) {

	p := NewPrincipalFromList(NewClaimsList("sub", "user123").Add("email", "user@example.com"))

	require.Equal(t, "user123", p.Subject())
	require.Equal(t, "user@example.com", p.Email())
}

func TestNewPrincipal_ClaimAccess(t *testing.T) {
	now := time.Now().Unix()
	cs := NewClaimsSet("abc123").
		Set("exp", strconv.FormatInt(now+3600, 10)).
		Set("aud", "api1,api2").
		Set("scopes", "read,write")

	p := NewPrincipal(cs)

	require.Equal(t, "abc123", p.Subject())
	require.ElementsMatch(t, []string{"api1", "api2"}, p.Audience())
	require.ElementsMatch(t, []string{"read", "write"}, p.Scopes())
	require.Equal(t, now+3600, p.ExpirationTime())
}

func TestPrincipal_CustomClaim(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")
	p := NewPrincipal(cs)

	claim := p.CustomClaim("foo")
	require.Equal(t, "bar", claim.Value())

	val := p.CustomClaimValue("foo")
	require.Equal(t, "bar", val)

	missing := p.CustomClaim("missing")
	require.Equal(t, "", missing.Value())
}

func TestPrincipal_ClaimsCopy(t *testing.T) {
	cs := NewClaimsSet("copyme")
	p := NewPrincipal(cs)

	claimsMap := p.Claims()
	claimsMap["sub"] = NewClaim("sub", "tampered")

	// Original Principal should not be affected
	require.Equal(t, "copyme", p.Subject())
}
