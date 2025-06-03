package claims

import (
	"maps"
	"sort"
	"strconv"
	"strings"
)

type ClaimSet struct {
	state map[string]Claim
}

func MakeClaimsSet(len int) *ClaimSet {
	return &ClaimSet{state: make(map[string]Claim, len)}
}

// NewClaimsSet creates a new ClaimSet with a subject claim.
func NewClaimsSet(subject string) *ClaimSet {
	cs := &ClaimSet{state: make(map[string]Claim)}
	cs.Set(sub, subject)
	return cs
}

func (cs *ClaimSet) Set(key, value string) *ClaimSet {
	cs.state[key] = NewClaim(key, value)
	return cs
}

// Get returns a claim and a boolean indicating if it exists.
func (cs *ClaimSet) Get(key string) (Claim, bool) {
	c, ok := cs.state[key]
	return c, ok
}

func (cs *ClaimSet) Value(key string) string {
	if c, ok := cs.state[key]; ok {
		return c.Value()
	}
	return ""
}

func (cs *ClaimSet) Range(fn func(key string, claim Claim)) {
	for k, v := range cs.state {
		fn(k, v)
	}
}

// Core getters
func (cs *ClaimSet) Subject() string       { return cs.Value(sub) }
func (cs *ClaimSet) Issuer() string        { return cs.Value(iss) }
func (cs *ClaimSet) JWTI() string          { return cs.Value(jti) }
func (cs *ClaimSet) Email() string         { return cs.Value(email) }
func (cs *ClaimSet) Username() string      { return cs.Value(name) }
func (cs *ClaimSet) ExpirationTime() int64 { return cs.int64(exp) }
func (cs *ClaimSet) NotBefore() int64      { return cs.int64(nbf) }
func (cs *ClaimSet) IssuedAt() int64       { return cs.int64(iat) }

func (cs *ClaimSet) Audience() []string {
	return cs.splitList(aud)
}

func (cs *ClaimSet) Roles() []string {
	return cs.splitList(roles)
}

func (cs *ClaimSet) Scopes() []string {
	return cs.splitList(scope)
}

func (cs *ClaimSet) SetSubject(v string) *ClaimSet   { return cs.Set(sub, v) }
func (cs *ClaimSet) SetIssuer(v string) *ClaimSet    { return cs.Set(iss, v) }
func (cs *ClaimSet) SetAudience(v string) *ClaimSet  { return cs.Set(aud, v) }
func (cs *ClaimSet) SetExpiration(v int64) *ClaimSet { return cs.Set(exp, int64ToString(v)) }
func (cs *ClaimSet) SetNotBefore(v int64) *ClaimSet  { return cs.Set(nbf, int64ToString(v)) }
func (cs *ClaimSet) SetIssuedAt(v int64) *ClaimSet   { return cs.Set(iat, int64ToString(v)) }
func (cs *ClaimSet) SetTokenID(v string) *ClaimSet   { return cs.Set(jti, v) }
func (cs *ClaimSet) SetEmail(v string) *ClaimSet     { return cs.Set(email, v) }
func (cs *ClaimSet) SetName(v string) *ClaimSet      { return cs.Set(name, v) }

func (cs *ClaimSet) SetRoles(values ...string) *ClaimSet {
	return cs.Set(roles, strings.Join(values, ","))
}

func (cs *ClaimSet) SetScopes(values ...string) *ClaimSet {
	return cs.Set(scope, strings.Join(values, ","))
}

func (cs *ClaimSet) AppendRoles(values ...string) *ClaimSet {
	existing := cs.Roles()
	return cs.SetRoles(mergeAndDedupe(existing, values)...)
}

func (cs *ClaimSet) AppendScopes(values ...string) *ClaimSet {
	existing := cs.Scopes()
	return cs.SetScopes(mergeAndDedupe(existing, values)...)
}

func (cs *ClaimSet) CustomClaim(name string) Claim {
	if c, ok := cs.state[name]; ok {
		return c
	}
	return NewClaim("", "")
}

func (cs *ClaimSet) CustomClaimValue(name string) string {
	return cs.CustomClaim(name).Value()
}

func (cs *ClaimSet) Claims() *ClaimSet {
	clone := make(map[string]Claim, len(cs.state))
	maps.Copy(clone, cs.state)
	return &ClaimSet{state: clone}
}

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
