package claims

import (
	"maps"
)

// Principal represents an authenticated identity with associated claims.
type Principal interface {
	// Subject returns the unique identifier for the subject (e.g., user ID).
	Subject() string

	// Issuer returns the entity that issued the token.
	Issuer() string

	// Audience returns the intended audience(s) of the token.
	Audience() []string

	// ExpirationTime returns the token expiration time (Unix timestamp).
	ExpirationTime() int64

	// NotBefore returns the time before which the token is not valid (Unix timestamp).
	NotBefore() int64

	// IssuedAt returns the time at which the token was issued (Unix timestamp).
	IssuedAt() int64

	// JWTI returns the unique token ID.
	JWTI() string

	// Scopes returns the list of scopes or permissions granted.
	Scopes() []string

	// Roles returns the roles assigned to the subject.
	Roles() []string

	// Email returns the email address of the subject.
	Email() string

	// Username returns the human-readable name of the subject.
	Username() string

	// CustomClaim retrieves a custom claim by name.
	CustomClaim(name string) Claim

	// CustomClaimValue returns the string value of a custom claim.
	CustomClaimValue(name string) string

	// Claims returns a copy of the underlying claim set.
	Claims() ClaimSet
}

// NewPrincipalFromList constructs a Principal from a ClaimList and optional TTL for exp.
func NewPrincipalFromList(claimList ClaimList) Principal {
	claimSet := ToClaimSet(claimList)
	return NewPrincipal(claimSet)
}

// NewPrincipal constructs a Principal from a ClaimSet and optional TTL for exp.
func NewPrincipal(claimSet ClaimSet) Principal {
	cloneSet := make(ClaimSet, len(claimSet))
	maps.Copy(cloneSet, claimSet)
	return &principal{
		claimSet: cloneSet,
	}
}

type principal struct {
	claimSet ClaimSet
}

// Subject returns the "sub" claim.
func (cp *principal) Subject() string {
	return cp.getClaimString(sub)
}

// Issuer returns the "iss" claim.
func (cp *principal) Issuer() string {
	return cp.getClaimString(iss)
}

// Audience returns the "aud" claim as a string slice.
func (cp *principal) Audience() []string {
	if claim, exists := cp.claimSet[aud]; exists {
		return claim.Values(",")
	}
	return []string{}
}

// ExpirationTime returns the "exp" claim as int64.
func (cp *principal) ExpirationTime() int64 {
	return cp.getClaimInt64(exp)
}

// NotBefore returns the "nbf" claim as int64.
func (cp *principal) NotBefore() int64 {
	return cp.getClaimInt64(nbf)
}

// IssuedAt returns the "iat" claim as int64.
func (cp *principal) IssuedAt() int64 {
	return cp.getClaimInt64(iat)
}

// JWTI returns the "jti" claim.
func (cp *principal) JWTI() string {
	return cp.getClaimString(jti)
}

// Scopes returns the "scopes" claim as a string slice.
func (cp *principal) Scopes() []string {
	if claim, exists := cp.claimSet[scope]; exists {
		return claim.Values(",")
	}
	return []string{}
}

// Roles returns the "roles" claim as a string slice.
func (cp *principal) Roles() []string {
	if claim, exists := cp.claimSet[roles]; exists {
		return claim.Values(",")
	}
	return []string{}
}

// Email returns the "email" claim.
func (cp *principal) Email() string {
	return cp.getClaimString(email)
}

// Username returns the "name" claim.
func (cp *principal) Username() string {
	return cp.getClaimString(name)
}

// CustomClaim returns a claim by name or an empty claim if not present.
func (cp *principal) CustomClaim(name string) Claim {
	if claim, exists := cp.claimSet[name]; exists {
		return claim
	}
	return NewClaim("", "")
}

// CustomClaimValue returns the string value of a named claim.
func (cp *principal) CustomClaimValue(name string) string {
	return cp.CustomClaim(name).Value()
}

// Claims returns a copy of the underlying claim set.
func (cp *principal) Claims() ClaimSet {
	cloneSet := make(ClaimSet, len(cp.claimSet))
	maps.Copy(cloneSet, cp.claimSet)
	return cloneSet
}

// getClaimString safely retrieves a string claim.
func (cp *principal) getClaimString(claimName string) string {
	if claim, exists := cp.claimSet[claimName]; exists {
		return claim.Value()
	}
	return ""
}

// getClaimInt64 safely retrieves an int64 claim.
func (cp *principal) getClaimInt64(claimName string) int64 {
	if claim, exists := cp.claimSet[claimName]; exists {
		if value, ok := claim.Int64Value(); ok {
			return value
		}
	}
	return 0
}
