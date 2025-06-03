package claims

import (
	"sort"
	"strconv"
	"strings"
)

type ClaimSet map[string]Claim

// NewClaimsSet creates a new ClaimSet with a subject claim.
func NewClaimsSet(subject string) ClaimSet {
	cs := ClaimSet{sub: NewClaim(sub, subject)}
	return cs
}

// Set adds or updates a claim and returns the updated ClaimSet.
func (cs ClaimSet) Set(key, value string) ClaimSet {
	(cs)[key] = NewClaim(key, value)
	return cs
}

// Developer-friendly claim setters
func (cs ClaimSet) SetSubject(value string) ClaimSet   { return cs.Set(sub, value) }
func (cs ClaimSet) SetIssuer(value string) ClaimSet    { return cs.Set(iss, value) }
func (cs ClaimSet) SetAudience(value string) ClaimSet  { return cs.Set(aud, value) }
func (cs ClaimSet) SetExpiration(value int64) ClaimSet { return cs.Set(exp, int64ToString(value)) }
func (cs ClaimSet) SetNotBefore(value int64) ClaimSet  { return cs.Set(nbf, int64ToString(value)) }
func (cs ClaimSet) SetIssuedAt(value int64) ClaimSet   { return cs.Set(iat, int64ToString(value)) }
func (cs ClaimSet) SetTokenID(value string) ClaimSet   { return cs.Set(jti, value) }
func (cs ClaimSet) SetEmail(value string) ClaimSet     { return cs.Set(email, value) }
func (cs ClaimSet) SetName(value string) ClaimSet      { return cs.Set(name, value) }

func (cs ClaimSet) SetRoles(values ...string) ClaimSet {
	return cs.Set(roles, strings.Join(values, ","))
}

func (cs ClaimSet) AppendRoles(values ...string) ClaimSet {
	existing := strings.Split((cs)[roles].Value(), ",")
	merged := mergeAndDedupe(existing, values)
	return cs.Set(roles, strings.Join(merged, ","))
}

func (cs ClaimSet) SetScopes(values ...string) ClaimSet {
	return cs.Set(scope, strings.Join(values, ","))
}

func (cs ClaimSet) AppendScopes(values ...string) ClaimSet {
	existing := strings.Split((cs)[scope].Value(), ",")
	merged := mergeAndDedupe(existing, values)
	return cs.Set(scope, strings.Join(merged, ","))
}

// ToClaimList converts the ClaimSet to a ClaimList.
func (cs ClaimSet) ToClaimList() ClaimList {
	list := make(ClaimList, 0, len(cs))
	for _, c := range cs {
		list = append(list, c)
	}
	return list
}

func int64ToString(i int64) string {
	return strconv.FormatInt(i, 10)
}

func mergeAndDedupe(existing, additional []string) []string {
	seen := make(map[string]struct{})
	for _, v := range existing {
		v = strings.TrimSpace(v)
		if v != "" {
			seen[v] = struct{}{}
		}
	}
	for _, v := range additional {
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
