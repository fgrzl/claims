package claims

import "encoding/json"

type ClaimSet map[string]Claim

func NewClaimsSet(key, value string) ClaimSet {
	return ClaimSet{key: NewClaim(key, value)}
}

func (cs ClaimSet) Set(key, value string) ClaimSet {
	copy := make(ClaimSet, len(cs))
	for k, v := range cs {
		copy[k] = v
	}
	copy[key] = NewClaim(key, value)
	return copy
}

func (cs ClaimSet) ToClaimList() ClaimList {
	list := make(ClaimList, 0, len(cs))
	for _, c := range cs {
		list = append(list, c)
	}
	return list
}

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

	result := make(ClaimSet, len(raw))
	for k, v := range raw {
		result[k] = NewClaim(k, v)
	}
	*cs = result
	return nil
}
