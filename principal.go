package claims

import (
	"encoding/json"
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

// SerializablePrincipal represents the serializable fields of a Principal
// This is used for serializing user principal data in message headers
type SerializablePrincipal struct {
	Subject        string   `json:"subject"`
	Issuer         string   `json:"issuer"`
	Audience       []string `json:"audience"`
	Scopes         []string `json:"scopes"`
	Roles          []string `json:"roles"`
	Email          string   `json:"email"`
	Username       string   `json:"username"`
	ExpirationTime int64    `json:"exp"`
	NotBefore      int64    `json:"nbf"`
	IssuedAt       int64    `json:"iat"`
	JWTI           string   `json:"jti"`
}

// ToSerializablePrincipal converts a Principal to a SerializablePrincipal
func ToSerializablePrincipal(p Principal) SerializablePrincipal {
	return SerializablePrincipal{
		Subject:        p.Subject(),
		Issuer:         p.Issuer(),
		Audience:       p.Audience(),
		Scopes:         p.Scopes(),
		Roles:          p.Roles(),
		Email:          p.Email(),
		Username:       p.Username(),
		ExpirationTime: p.ExpirationTime(),
		NotBefore:      p.NotBefore(),
		IssuedAt:       p.IssuedAt(),
		JWTI:           p.JWTI(),
	}
}

// SerializePrincipal serializes a Principal to JSON string
func SerializePrincipal(p Principal) (string, error) {
	serializable := ToSerializablePrincipal(p)
	data, err := json.Marshal(serializable)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializePrincipalFields deserializes a JSON string to SerializablePrincipal
func DeserializePrincipalFields(jsonStr string) (*SerializablePrincipal, error) {
	var sp SerializablePrincipal
	if err := json.Unmarshal([]byte(jsonStr), &sp); err != nil {
		return nil, err
	}
	return &sp, nil
}

// ReconstructedPrincipal implements Principal from deserialized data
type ReconstructedPrincipal struct {
	fields SerializablePrincipal
}

// NewReconstructedPrincipal creates a new ReconstructedPrincipal from SerializablePrincipal
func NewReconstructedPrincipal(fields SerializablePrincipal) *ReconstructedPrincipal {
	return &ReconstructedPrincipal{fields: fields}
}

// Subject implements Principal
func (r *ReconstructedPrincipal) Subject() string { return r.fields.Subject }

// Issuer implements Principal
func (r *ReconstructedPrincipal) Issuer() string { return r.fields.Issuer }

// Audience implements Principal
func (r *ReconstructedPrincipal) Audience() []string { return r.fields.Audience }

// ExpirationTime implements Principal
func (r *ReconstructedPrincipal) ExpirationTime() int64 { return r.fields.ExpirationTime }

// NotBefore implements Principal
func (r *ReconstructedPrincipal) NotBefore() int64 { return r.fields.NotBefore }

// IssuedAt implements Principal
func (r *ReconstructedPrincipal) IssuedAt() int64 { return r.fields.IssuedAt }

// JWTI implements Principal
func (r *ReconstructedPrincipal) JWTI() string { return r.fields.JWTI }

// Scopes implements Principal
func (r *ReconstructedPrincipal) Scopes() []string { return r.fields.Scopes }

// Roles implements Principal
func (r *ReconstructedPrincipal) Roles() []string { return r.fields.Roles }

// Email implements Principal
func (r *ReconstructedPrincipal) Email() string { return r.fields.Email }

// Username implements Principal
func (r *ReconstructedPrincipal) Username() string { return r.fields.Username }

// CustomClaim implements Principal (returns nil for reconstructed principals)
func (r *ReconstructedPrincipal) CustomClaim(name string) Claim { return nil }

// CustomClaimValue implements Principal (returns empty string for reconstructed principals)
func (r *ReconstructedPrincipal) CustomClaimValue(name string) string { return "" }

// Claims implements Principal (returns nil for reconstructed principals)
func (r *ReconstructedPrincipal) Claims() *ClaimSet { return nil }

// DeserializePrincipal deserializes a JSON string to a Principal
func DeserializePrincipal(jsonStr string) (Principal, error) {
	fields, err := DeserializePrincipalFields(jsonStr)
	if err != nil {
		return nil, err
	}
	return NewReconstructedPrincipal(*fields), nil
}
