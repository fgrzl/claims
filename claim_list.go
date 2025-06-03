package claims

type ClaimList []Claim

func NewClaimsList(key, value string) ClaimList {
	return ClaimList{NewClaim(key, value)}
}

func (cl ClaimList) Add(key, value string) ClaimList {
	return append(cl, NewClaim(key, value))
}

func ToClaimSet(cl ClaimList) *ClaimSet {
	set := &ClaimSet{
		state: make(map[string]Claim, len(cl)),
	}
	for _, c := range cl {
		set.state[c.Name()] = c
	}
	return set
}
