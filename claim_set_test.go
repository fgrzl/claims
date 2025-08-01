package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClaimsSet(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")

	require.Equal(t, "tester", (cs.state)[sub].Value())
	require.Equal(t, "bar", (cs.state)["foo"].Value())
}

func TestClaimSetSet(t *testing.T) {
	cs := NewClaimsSet("tester").Set("foo", "bar")
	cs.Set("baz", "qux") // same instance is mutated

	require.Equal(t, "bar", (cs.state)["foo"].Value())
	require.Equal(t, "qux", (cs.state)["baz"].Value())
}

func TestToClaimList(t *testing.T) {
	cs := NewClaimsSet("tester").Set("a", "1").Set("b", "2")
	list := cs.ToClaimList()

	names := map[string]bool{}
	for _, c := range list {
		names[c.Name()] = true
	}
	require.True(t, names["a"])
	require.True(t, names["b"])
}

func TestMakeClaimsSet(t *testing.T) {
	// Arrange & Act
	cs := MakeClaimsSet(10)

	// Assert
	assert.NotNil(t, cs)
	assert.NotNil(t, cs.state)
	assert.Equal(t, 0, len(cs.state))
}

func TestClaimSet_Get(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").Set("email", "user@example.com")

	// Act & Assert
	claim, exists := cs.Get("email")
	assert.True(t, exists)
	assert.Equal(t, "email", claim.Name())
	assert.Equal(t, "user@example.com", claim.Value())

	// Test non-existent claim
	missingClaim, exists := cs.Get("missing")
	assert.False(t, exists)
	assert.Nil(t, missingClaim)
}

func TestClaimSet_Value(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").Set("email", "user@example.com")

	// Act & Assert
	assert.Equal(t, "user@example.com", cs.Value("email"))
	assert.Equal(t, "", cs.Value("missing"))
}

func TestClaimSet_Range(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").Set("email", "user@example.com").Set("role", "admin")
	collected := make(map[string]string)

	// Act
	cs.Range(func(key string, claim Claim) {
		collected[key] = claim.Value()
	})

	// Assert
	expected := map[string]string{
		"sub":   "user123",
		"email": "user@example.com",
		"role":  "admin",
	}
	assert.Equal(t, expected, collected)
}

func TestClaimSet_CoreGetters(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").
		SetIssuer("test-issuer").
		SetEmail("user@example.com").
		SetTokenID("token-123").
		SetName("Test User").
		SetExpiration(1234567890).
		SetNotBefore(1234567800).
		SetIssuedAt(1234567850)

	// Act & Assert
	assert.Equal(t, "user123", cs.Subject())
	assert.Equal(t, "test-issuer", cs.Issuer())
	assert.Equal(t, "user@example.com", cs.Email())
	assert.Equal(t, "token-123", cs.JWTI())
	assert.Equal(t, "Test User", cs.Username())
	assert.Equal(t, int64(1234567890), cs.ExpirationTime())
	assert.Equal(t, int64(1234567800), cs.NotBefore())
	assert.Equal(t, int64(1234567850), cs.IssuedAt())
}

func TestClaimSet_ArrayClaims(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").
		SetAudience("api1,api2,api3").
		SetRoles("admin", "user", "guest").
		SetScopes("read", "write", "delete")

	// Act & Assert
	assert.Equal(t, []string{"api1", "api2", "api3"}, cs.Audience())
	assert.Equal(t, []string{"admin", "user", "guest"}, cs.Roles())
	assert.Equal(t, []string{"read", "write", "delete"}, cs.Scopes())
}

func TestClaimSet_AppendRoles(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").SetRoles("user", "guest")

	// Act
	cs.AppendRoles("admin", "user") // "user" is duplicate

	// Assert
	roles := cs.Roles()
	// Should be sorted and deduplicated
	assert.Equal(t, []string{"admin", "guest", "user"}, roles)
}

func TestClaimSet_AppendScopes(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").SetScopes("read")

	// Act
	cs.AppendScopes("write", "read", "delete") // "read" is duplicate

	// Assert
	scopes := cs.Scopes()
	// Should be sorted and deduplicated
	assert.Equal(t, []string{"delete", "read", "write"}, scopes)
}

func TestClaimSet_CustomClaim(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").Set("custom_field", "custom_value")

	// Act & Assert
	customClaim := cs.CustomClaim("custom_field")
	assert.Equal(t, "custom_field", customClaim.Name())
	assert.Equal(t, "custom_value", customClaim.Value())

	// Test missing custom claim
	missingClaim := cs.CustomClaim("missing_field")
	assert.Equal(t, "", missingClaim.Name())
	assert.Equal(t, "", missingClaim.Value())
}

func TestClaimSet_CustomClaimValue(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").Set("custom_field", "custom_value")

	// Act & Assert
	assert.Equal(t, "custom_value", cs.CustomClaimValue("custom_field"))
	assert.Equal(t, "", cs.CustomClaimValue("missing_field"))
}

func TestClaimSet_Claims_ReturnsDeepCopy(t *testing.T) {
	// Arrange
	original := NewClaimsSet("user123").Set("email", "user@example.com")

	// Act
	copy := original.Claims()
	copy.SetSubject("tampered")
	copy.SetEmail("tampered@example.com")

	// Assert
	// Original should not be affected
	assert.Equal(t, "user123", original.Subject())
	assert.Equal(t, "user@example.com", original.Email())
	
	// Copy should have the changes
	assert.Equal(t, "tampered", copy.Subject())
	assert.Equal(t, "tampered@example.com", copy.Email())
}

func TestClaimSet_SettersReturnSameInstance(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123")
	
	// Act - test method chaining
	result := cs.SetIssuer("test-issuer").
		SetEmail("user@example.com").
		SetExpiration(1234567890)

	// Assert
	assert.Same(t, cs, result) // Should be the same instance
	assert.Equal(t, "test-issuer", cs.Issuer())
	assert.Equal(t, "user@example.com", cs.Email())
	assert.Equal(t, int64(1234567890), cs.ExpirationTime())
}

func TestClaimSet_EmptyArrayClaims(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123")

	// Act & Assert
	assert.Nil(t, cs.Audience())
	assert.Nil(t, cs.Roles())
	assert.Nil(t, cs.Scopes())
}

func TestClaimSet_ArrayClaimsWithEmptyStrings(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123")

	// Act
	cs.SetRoles("", "admin", "", "user", "")
	cs.SetScopes("", "read", "", "write", "")

	// Assert
	// The current implementation splits by comma, so empty strings are preserved
	assert.Equal(t, []string{"", "admin", "", "user", ""}, cs.Roles())
	assert.Equal(t, []string{"", "read", "", "write", ""}, cs.Scopes())
}

func TestClaimSet_int64_InvalidValue(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123").Set("exp", "invalid_number")

	// Act & Assert
	assert.Equal(t, int64(0), cs.ExpirationTime())
}

func TestClaimSet_splitList_EmptyClaim(t *testing.T) {
	// Arrange
	cs := NewClaimsSet("user123")

	// Act & Assert
	assert.Nil(t, cs.Audience()) // aud claim doesn't exist
}
