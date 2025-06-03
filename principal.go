package claims

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
	Claims() *ClaimSet
}

// NewPrincipalFromList constructs a Principal from a ClaimList.
func NewPrincipalFromList(claimList ClaimList) Principal {
	return NewPrincipal(ToClaimSet(claimList))
}

// NewPrincipal constructs a Principal from a ClaimSet.
func NewPrincipal(claimSet *ClaimSet) Principal {
	// Deep copy
	clone := &ClaimSet{state: make(map[string]Claim, len(claimSet.state))}
	for k, v := range claimSet.state {
		clone.state[k] = v
	}
	return &principal{claimSet: clone}
}

type principal struct {
	claimSet *ClaimSet
}

func (cp *principal) Subject() string       { return cp.claimSet.Subject() }
func (cp *principal) Issuer() string        { return cp.claimSet.Issuer() }
func (cp *principal) Audience() []string    { return cp.claimSet.Audience() }
func (cp *principal) ExpirationTime() int64 { return cp.claimSet.ExpirationTime() }
func (cp *principal) NotBefore() int64      { return cp.claimSet.NotBefore() }
func (cp *principal) IssuedAt() int64       { return cp.claimSet.IssuedAt() }
func (cp *principal) JWTI() string          { return cp.claimSet.JWTI() }
func (cp *principal) Scopes() []string      { return cp.claimSet.Scopes() }
func (cp *principal) Roles() []string       { return cp.claimSet.Roles() }
func (cp *principal) Email() string         { return cp.claimSet.Email() }
func (cp *principal) Username() string      { return cp.claimSet.Username() }
func (cp *principal) CustomClaim(name string) Claim {
	return cp.claimSet.CustomClaim(name)
}
func (cp *principal) CustomClaimValue(name string) string {
	return cp.claimSet.CustomClaimValue(name)
}
func (cp *principal) Claims() *ClaimSet {
	return cp.claimSet.Claims()
}
