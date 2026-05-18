package claims

import (
	"maps"
	"sort"
	"strconv"
	"strings"
)

// ClaimSet represents a collection of claims stored as key-value pairs.
// It provides methods to set, get, and access claims in various formats.
type ClaimSet struct {
	state map[string]Claim
}

// MakeClaimsSet creates a new ClaimSet with the specified initial capacity.
func MakeClaimsSet(capacity int) *ClaimSet {
	return &ClaimSet{state: make(map[string]Claim, capacity)}
}

// NewClaimsSet creates a new ClaimSet with a subject claim.
func NewClaimsSet(subject string) *ClaimSet {
	cs := &ClaimSet{state: make(map[string]Claim)}
	cs.Set(sub, subject)
	return cs
}

// Set adds or updates a claim with the specified key and value.
// Returns the same ClaimSet instance for method chaining.
func (cs *ClaimSet) Set(key, value string) *ClaimSet {
	cs.state[key] = NewClaim(key, value)
	return cs
}

// Get returns a claim and a boolean indicating if it exists.
func (cs *ClaimSet) Get(key string) (Claim, bool) {
	c, ok := cs.state[key]
	return c, ok
}

// Value returns the string value of the claim with the specified key.
// Returns an empty string if the claim does not exist.
func (cs *ClaimSet) Value(key string) string {
	if c, ok := cs.state[key]; ok {
		return c.Value()
	}
	return ""
}

// Range calls the provided function for each claim in the ClaimSet.
func (cs *ClaimSet) Range(fn func(key string, claim Claim)) {
	for k, v := range cs.state {
		fn(k, v)
	}
}

// Subject returns the subject claim value.
func (cs *ClaimSet) Subject() string { return cs.Value(sub) }

// Issuer returns the issuer claim value.
func (cs *ClaimSet) Issuer() string { return cs.Value(iss) }

// JWTI returns the JWT ID claim value.
func (cs *ClaimSet) JWTI() string { return cs.Value(jti) }

// Email returns the email claim value.
func (cs *ClaimSet) Email() string { return cs.Value(email) }

// Username returns the username claim value.
func (cs *ClaimSet) Username() string { return cs.Value(name) }

// ExpirationTime returns the expiration time claim as a Unix timestamp.
func (cs *ClaimSet) ExpirationTime() int64 { return cs.int64(exp) }

// NotBefore returns the not before claim as a Unix timestamp.
func (cs *ClaimSet) NotBefore() int64 { return cs.int64(nbf) }

// IssuedAt returns the issued at claim as a Unix timestamp.
func (cs *ClaimSet) IssuedAt() int64 { return cs.int64(iat) }

// Audience returns the audience claim as a slice of strings.
func (cs *ClaimSet) Audience() []string {
	return cs.splitList(aud)
}

// Roles returns the roles claim as a slice of strings.
func (cs *ClaimSet) Roles() []string {
	return cs.splitList(roles)
}

// Scopes returns the scopes claim as a slice of strings.
func (cs *ClaimSet) Scopes() []string {
	return cs.splitList(scope)
}

// SetSubject sets the subject claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetSubject(v string) *ClaimSet { return cs.Set(sub, v) }

// SetIssuer sets the issuer claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetIssuer(v string) *ClaimSet { return cs.Set(iss, v) }

// SetAudience sets the audience claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetAudience(v string) *ClaimSet { return cs.Set(aud, v) }

// SetExpiration sets the expiration time claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetExpiration(v int64) *ClaimSet { return cs.Set(exp, int64ToString(v)) }

// SetNotBefore sets the not before claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetNotBefore(v int64) *ClaimSet { return cs.Set(nbf, int64ToString(v)) }

// SetIssuedAt sets the issued at claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetIssuedAt(v int64) *ClaimSet { return cs.Set(iat, int64ToString(v)) }

// SetTokenID sets the JWT ID claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetTokenID(v string) *ClaimSet { return cs.Set(jti, v) }

// SetEmail sets the email claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetEmail(v string) *ClaimSet { return cs.Set(email, v) }

// SetName sets the name claim and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetName(v string) *ClaimSet { return cs.Set(name, v) }

// SetRoles sets the roles claim with the provided values and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetRoles(values ...string) *ClaimSet {
	return cs.Set(roles, strings.Join(values, ","))
}

// SetScopes sets the scopes claim with the provided values and returns the ClaimSet for chaining.
func (cs *ClaimSet) SetScopes(values ...string) *ClaimSet {
	return cs.Set(scope, strings.Join(values, ","))
}

// AppendRoles appends new roles to existing roles and returns the ClaimSet for chaining.
func (cs *ClaimSet) AppendRoles(values ...string) *ClaimSet {
	existing := cs.Roles()
	return cs.SetRoles(mergeAndDedupe(existing, values)...)
}

// AppendScopes appends new scopes to existing scopes and returns the ClaimSet for chaining.
func (cs *ClaimSet) AppendScopes(values ...string) *ClaimSet {
	existing := cs.Scopes()
	return cs.SetScopes(mergeAndDedupe(existing, values)...)
}

// CustomClaim returns a custom claim by name, or an empty claim if not found.
func (cs *ClaimSet) CustomClaim(name string) Claim {
	if c, ok := cs.state[name]; ok {
		return c
	}
	return NewClaim("", "")
}

// CustomClaimValue returns the string value of a custom claim by name.
func (cs *ClaimSet) CustomClaimValue(name string) string {
	return cs.CustomClaim(name).Value()
}

// Claims returns a deep copy of the ClaimSet.
func (cs *ClaimSet) Claims() *ClaimSet {
	clone := make(map[string]Claim, len(cs.state))
	maps.Copy(clone, cs.state)
	return &ClaimSet{state: clone}
}

// ToClaimList converts the ClaimSet to a ClaimList.
func (cs *ClaimSet) ToClaimList() ClaimList {
	list := make(ClaimList, 0, len(cs.state))
	for _, c := range cs.state {
		list = append(list, c)
	}
	return list
}

// Helpers
func (cs *ClaimSet) splitList(key string) []string {
	if claim, ok := cs.state[key]; ok {
		return claim.Values(",")
	}
	return nil
}

func (cs *ClaimSet) int64(key string) int64 {
	if claim, ok := cs.state[key]; ok {
		if val, ok := claim.Int64Value(); ok {
			return val
		}
	}
	return 0
}

func int64ToString(i int64) string {
	return strconv.FormatInt(i, 10)
}

func mergeAndDedupe(existing, additional []string) []string {
	seen := make(map[string]struct{})
	for _, v := range append(existing, additional...) {
		v = strings.TrimSpace(v)
		if v != "" {
			seen[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
