package claims

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewPrincipalFromList(t *testing.T) {
	ttl := 1 * time.Hour
	p := NewPrincipalFromList(
		NewClaimsList("sub", "user123").Add("email", "user@example.com"),
		&ttl,
	)

	require.Equal(t, "user123", p.Subject())
	require.Equal(t, "user@example.com", p.Email())
	require.NotZero(t, p.ExpirationTime())
}

func TestNewPrincipal_ClaimAccess(t *testing.T) {
	now := time.Now().Unix()
	cs := NewClaimsSet("sub", "abc123").
		Set("exp", strconv.FormatInt(now+3600, 10)).
		Set("aud", "api1,api2").
		Set("scopes", "read,write")

	p := NewPrincipal(cs, nil)

	require.Equal(t, "abc123", p.Subject())
	require.ElementsMatch(t, []string{"api1", "api2"}, p.Audience())
	require.ElementsMatch(t, []string{"read", "write"}, p.Scopes())
	require.Equal(t, now+3600, p.ExpirationTime())
}

func TestPrincipal_CustomClaim(t *testing.T) {
	cs := NewClaimsSet("foo", "bar")
	p := NewPrincipal(cs, nil)

	claim := p.CustomClaim("foo")
	require.Equal(t, "bar", claim.Value())

	val := p.CustomClaimValue("foo")
	require.Equal(t, "bar", val)

	missing := p.CustomClaim("missing")
	require.Equal(t, "", missing.Value())
}

func TestPrincipal_ClaimsCopy(t *testing.T) {
	cs := NewClaimsSet("sub", "copyme")
	p := NewPrincipal(cs, nil)

	claimsMap := p.Claims()
	claimsMap["sub"] = NewClaim("sub", "tampered")

	// Original Principal should not be affected
	require.Equal(t, "copyme", p.Subject())
}

func TestPrincipal_JSONRoundTrip(t *testing.T) {
	original := NewClaimsSet("sub", "abc").Set("scopes", "read")

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded ClaimSet
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	p := NewPrincipal(decoded, nil)
	require.Equal(t, "abc", p.Subject())
	require.Equal(t, []string{"read"}, p.Scopes())
}
