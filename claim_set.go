package claims

import (
	"encoding/json"
	"strconv"
	"strings"
)

type ClaimSet map[string]Claim

func NewClaimsSet(key, value string) ClaimSet {
	return ClaimSet{key: NewClaim(key, value)}
}

// Set returns a copy of the ClaimSet with the new key/value inserted.
func (cs ClaimSet) Set(key, value string) ClaimSet {
	clone := make(ClaimSet, len(cs))
	for k, v := range cs {
		clone[k] = v
	}
	clone[key] = NewClaim(key, value)
	return clone
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
func (cs ClaimSet) SetScopes(values ...string) ClaimSet {
	return cs.Set(scope, strings.Join(values, ","))
}

// Converts the claim set to a flat list.
func (cs ClaimSet) ToClaimList() ClaimList {
	list := make(ClaimList, 0, len(cs))
	for _, c := range cs {
		list = append(list, c)
	}
	return list
}

// Marshal as a string map for JSON.
func (cs ClaimSet) MarshalJSON() ([]byte, error) {
	m := make(map[string]string, len(cs))
	for k, v := range cs {
		m[k] = v.Value()
	}
	return json.Marshal(m)
}

func (cs *ClaimSet) UnmarshalJSON(data []byte) error {
	raw := map[string]string{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	clone := make(ClaimSet, len(raw))
	for k, v := range raw {
		clone[k] = NewClaim(k, v)
	}
	*cs = clone
	return nil
}

func int64ToString(i int64) string {
	return strconv.FormatInt(i, 10)
}
