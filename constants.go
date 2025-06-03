package claims

const (
	// Standard JWT claim names
	sub   = "sub"    // Subject
	iss   = "iss"    // Issuer
	aud   = "aud"    // Audience
	exp   = "exp"    // Expiration time
	nbf   = "nbf"    // Not before
	iat   = "iat"    // Issued at
	jti   = "jti"    // JWT ID
	email = "email"  // Email of subject
	name  = "name"   // Name of subject
	roles = "roles"  // Roles assigned
	scope = "scopes" // Scopes granted
)
