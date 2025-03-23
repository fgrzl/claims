package claims

const (
	// Subject of the token (e.g., user ID)
	sub = "sub"

	// Issuer of the token
	iss = "iss"

	// Audience for which the token is intended
	aud = "aud"

	// Expiration time of the token (UNIX timestamp)
	exp = "exp"

	// Not Before time (UNIX timestamp)
	nbf = "nbf"

	// Issued At time (UNIX timestamp)
	iat = "iat"

	// JWT ID, a unique identifier for the token
	jti = "jti"

	// Email of the subject (if included in the claim)
	email = "email"

	// Name of the subject (if included in the claim)
	name = "name"

	// Roles assigned to the subject (if applicable)
	roles = "roles"

	// Scopes or permissions granted to the subject
	scope = "scope"
)

type Principal interface {
	// Unique identifier for the subject (e.g., user ID)
	Subject() string

	// Entity that issued the token
	Issuer() string

	// Intended audience(s) of the token
	Audience() []string

	// Token expiration time (Unix timestamp)
	ExpirationTime() int64

	// Time before which the token is not valid (Unix timestamp)
	NotBefore() int64

	// Time at which the token was issued (Unix timestamp)
	IssuedAt() int64

	// List of scopes or permissions granted
	Scopes() []string

	// Roles assigned to the subject
	Roles() []string

	// Email address of the subject
	Email() string

	// Username of the subject
	Username() string

	// Retrieve a custom claim by name
	CustomClaim(name string) Claim

	Claims() map[string]Claim

	JWT() string
}

func NewClaimsPrincipal(claims map[string]Claim) Principal {
	return &principal{
		claims: claims,
	}
}

type principal struct {
	claims map[string]Claim
}

func (cp *principal) Subject() string {
	return cp.getClaimString(sub)
}

func (cp *principal) Issuer() string {
	return cp.getClaimString(iss)
}

func (cp *principal) Audience() []string {
	if claim, exists := cp.claims[aud]; exists {
		return claim.Values(",")
	}
	return nil
}

func (cp *principal) ExpirationTime() int64 {
	return cp.getClaimInt64(exp)
}

func (cp *principal) NotBefore() int64 {
	return cp.getClaimInt64(nbf)
}

func (cp *principal) IssuedAt() int64 {
	return cp.getClaimInt64(iat)
}

func (cp *principal) JWTI() string {
	return cp.getClaimString(jti)
}

func (cp *principal) Scopes() []string {
	if claim, exists := cp.claims[scope]; exists {
		return claim.Values(",")
	}
	return nil
}

func (cp *principal) Roles() []string {
	if claim, exists := cp.claims[roles]; exists {
		return claim.Values(",")
	}

	return nil
}

func (cp *principal) Email() string {
	return cp.getClaimString(email)
}

func (cp *principal) Username() string {
	return cp.getClaimString(name)
}

func (cp *principal) CustomClaim(name string) Claim {
	if claim, exists := cp.claims[name]; exists {
		return claim
	}
	return NewClaim("", "")
}

func (cp *principal) Claims() map[string]Claim {
	return cp.claims
}

func (cp *principal) getClaimString(claimName string) string {
	if claim, exists := cp.claims[claimName]; exists {
		return claim.Value()
	}
	return ""
}

func (cp *principal) getClaimInt64(claimName string) int64 {
	if claim, exists := cp.claims[claimName]; exists {
		if value, ok := claim.Int64Value(); ok {
			return value
		}
	}
	return 0
}

func (cp *principal) JWT() string {

	// todo return the JWT string if available in the claims
	return ""
}
