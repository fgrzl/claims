package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldCreateClaimsListWhenGivenKeyAndValue(t *testing.T) {
	// Arrange
	key := "sub"
	value := "user123"

	// Act
	claimList := NewClaimsList(key, value)

	// Assert
	assert.Len(t, claimList, 1)
	assert.Equal(t, key, claimList[0].Name())
	assert.Equal(t, value, claimList[0].Value())
}

func TestShouldAddClaimWhenGivenKeyAndValue(t *testing.T) {
	// Arrange
	claimList := NewClaimsList("sub", "user123")

	// Act
	updatedList := claimList.Add("email", "user@example.com")

	// Assert
	assert.Len(t, updatedList, 2)
	
	// Check first claim
	assert.Equal(t, "sub", updatedList[0].Name())
	assert.Equal(t, "user123", updatedList[0].Value())
	
	// Check second claim
	assert.Equal(t, "email", updatedList[1].Name())
	assert.Equal(t, "user@example.com", updatedList[1].Value())
}

func TestShouldAddMultipleClaimsWhenChaining(t *testing.T) {
	// Arrange
	claimList := NewClaimsList("sub", "user123")

	// Act
	result := claimList.
		Add("email", "user@example.com").
		Add("roles", "admin,user").
		Add("exp", "1234567890")

	// Assert
	assert.Len(t, result, 4)
	
	expectedClaims := map[string]string{
		"sub":   "user123",
		"email": "user@example.com",
		"roles": "admin,user",
		"exp":   "1234567890",
	}
	
	for _, claim := range result {
		expectedValue, exists := expectedClaims[claim.Name()]
		assert.True(t, exists, "Unexpected claim: %s", claim.Name())
		assert.Equal(t, expectedValue, claim.Value())
	}
}

func TestShouldConvertToClaimSetWhenGivenClaimList(t *testing.T) {
	// Arrange
	claimList := NewClaimsList("sub", "user123").
		Add("email", "user@example.com").
		Add("roles", "admin,user")

	// Act
	claimSet := ToClaimSet(claimList)

	// Assert
	assert.NotNil(t, claimSet)
	
	// Check that all claims are accessible in the ClaimSet
	assert.Equal(t, "user123", claimSet.Subject())
	assert.Equal(t, "user@example.com", claimSet.Email())
	assert.Equal(t, []string{"admin", "user"}, claimSet.Roles())
}

func TestShouldCreateEmptyClaimSetWhenListIsEmpty(t *testing.T) {
	// Arrange
	var claimList ClaimList

	// Act
	claimSet := ToClaimSet(claimList)

	// Assert
	assert.NotNil(t, claimSet)
	assert.Equal(t, "", claimSet.Subject())
}

func TestShouldOverwriteValueWhenKeyIsDuplicated(t *testing.T) {
	// Arrange
	claimList := ClaimList{
		NewClaim("sub", "user123"),
		NewClaim("sub", "user456"), // duplicate key - should overwrite
		NewClaim("email", "user@example.com"),
	}

	// Act
	claimSet := ToClaimSet(claimList)

	// Assert
	// The last value should win for duplicate keys
	assert.Equal(t, "user456", claimSet.Subject())
	assert.Equal(t, "user@example.com", claimSet.Email())
}

func TestShouldIntegrateWithClaimSetWhenUsingComplexScenario(t *testing.T) {
	// Arrange
	claimList := NewClaimsList("sub", "testuser").
		Add("iss", "test-issuer").
		Add("aud", "api1,api2").
		Add("exp", "1234567890").
		Add("roles", "user,admin").
		Add("scopes", "read,write")

	// Act
	claimSet := ToClaimSet(claimList)

	// Assert
	assert.Equal(t, "testuser", claimSet.Subject())
	assert.Equal(t, "test-issuer", claimSet.Issuer())
	assert.Equal(t, []string{"api1", "api2"}, claimSet.Audience())
	assert.Equal(t, int64(1234567890), claimSet.ExpirationTime())
	assert.Equal(t, []string{"user", "admin"}, claimSet.Roles())
	assert.Equal(t, []string{"read", "write"}, claimSet.Scopes())
}