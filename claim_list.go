package claims

// ClaimList represents a slice of claims that can be built incrementally
// and converted to a ClaimSet.
type ClaimList []Claim

// NewClaimsList creates a new ClaimList with the initial key-value pair.
func NewClaimsList(key, value string) ClaimList {
	return ClaimList{NewClaim(key, value)}
}

// Add appends a new claim with the specified key and value to the ClaimList.
func (cl ClaimList) Add(key, value string) ClaimList {
	return append(cl, NewClaim(key, value))
}

// ToClaimSet converts a ClaimList to a ClaimSet for more efficient claim access.
func ToClaimSet(cl ClaimList) *ClaimSet {
	set := &ClaimSet{
		state: make(map[string]Claim, len(cl)),
	}
	for _, c := range cl {
		set.state[c.Name()] = c
	}
	return set
}
