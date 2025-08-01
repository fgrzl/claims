# API Reference

This document provides a comprehensive reference for all exported types and functions in the Claims library.

## Package: claims

### Types

#### Claim Interface

```go
type Claim interface {
    Name() string
    Value() string
    Values(sep string) []string
    IntValue() (int, bool)
    Int32Value() (int32, bool)
    Int64Value() (int64, bool)
    Float64Value() (float64, bool)
    BoolValue() (bool, bool)
    UUIDValue() (uuid.UUID, bool)
}
```

Represents a single claim with type conversion methods.

**Methods:**
- `Name()` - Returns the claim name
- `Value()` - Returns the claim value as string
- `Values(sep)` - Splits the value by separator and returns slice
- `IntValue()` - Converts to int, returns value and success flag
- `Int32Value()` - Converts to int32, returns value and success flag
- `Int64Value()` - Converts to int64, returns value and success flag
- `Float64Value()` - Converts to float64, returns value and success flag
- `BoolValue()` - Converts to bool, returns value and success flag
- `UUIDValue()` - Converts to UUID, returns value and success flag

#### ClaimSet

```go
type ClaimSet struct {
    // internal fields
}
```

A collection of claims with type-safe access methods.

**Constructor Functions:**
- `NewClaimsSet(subject string) *ClaimSet` - Creates new ClaimSet with subject
- `MakeClaimsSet(capacity int) *ClaimSet` - Creates new ClaimSet with initial capacity

**Core Methods:**
- `Set(key, value string) *ClaimSet` - Sets a claim (chainable)
- `Get(key string) (Claim, bool)` - Gets a claim by key
- `Value(key string) string` - Gets claim value as string
- `Range(fn func(string, Claim))` - Iterates over all claims

**Standard Claim Getters:**
- `Subject() string` - Gets "sub" claim
- `Issuer() string` - Gets "iss" claim
- `Audience() []string` - Gets "aud" claim as array
- `ExpirationTime() int64` - Gets "exp" claim as Unix timestamp
- `NotBefore() int64` - Gets "nbf" claim as Unix timestamp
- `IssuedAt() int64` - Gets "iat" claim as Unix timestamp
- `JWTI() string` - Gets "jti" claim
- `Email() string` - Gets "email" claim
- `Username() string` - Gets "name" claim
- `Roles() []string` - Gets "roles" claim as array
- `Scopes() []string` - Gets "scopes" claim as array

**Standard Claim Setters:**
- `SetSubject(v string) *ClaimSet` - Sets "sub" claim
- `SetIssuer(v string) *ClaimSet` - Sets "iss" claim
- `SetAudience(v string) *ClaimSet` - Sets "aud" claim
- `SetExpiration(v int64) *ClaimSet` - Sets "exp" claim
- `SetNotBefore(v int64) *ClaimSet` - Sets "nbf" claim
- `SetIssuedAt(v int64) *ClaimSet` - Sets "iat" claim
- `SetTokenID(v string) *ClaimSet` - Sets "jti" claim
- `SetEmail(v string) *ClaimSet` - Sets "email" claim
- `SetName(v string) *ClaimSet` - Sets "name" claim
- `SetRoles(values ...string) *ClaimSet` - Sets "roles" claim
- `SetScopes(values ...string) *ClaimSet` - Sets "scopes" claim

**Array Claim Methods:**
- `AppendRoles(values ...string) *ClaimSet` - Appends to existing roles
- `AppendScopes(values ...string) *ClaimSet` - Appends to existing scopes

**Custom Claim Methods:**
- `CustomClaim(name string) Claim` - Gets custom claim
- `CustomClaimValue(name string) string` - Gets custom claim value

**Utility Methods:**
- `Claims() *ClaimSet` - Returns deep copy
- `ToClaimList() ClaimList` - Converts to ClaimList

#### ClaimList

```go
type ClaimList []Claim
```

A slice of claims that can be built incrementally.

**Constructor Functions:**
- `NewClaimsList(key, value string) ClaimList` - Creates new list with initial claim

**Methods:**
- `Add(key, value string) ClaimList` - Adds a claim to the list

**Utility Functions:**
- `ToClaimSet(cl ClaimList) *ClaimSet` - Converts ClaimList to ClaimSet

#### Principal Interface

```go
type Principal interface {
    Subject() string
    Issuer() string
    Audience() []string
    ExpirationTime() int64
    NotBefore() int64
    IssuedAt() int64
    JWTI() string
    Scopes() []string
    Roles() []string
    Email() string
    Username() string
    CustomClaim(name string) Claim
    CustomClaimValue(name string) string
    Claims() *ClaimSet
}
```

Represents an authenticated identity with immutable access to claims.

**Constructor Functions:**
- `NewPrincipal(claimSet *ClaimSet) Principal` - Creates Principal from ClaimSet
- `NewPrincipalFromList(claimList ClaimList) Principal` - Creates Principal from ClaimList

#### SerializablePrincipal

```go
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
```

JSON-serializable representation of a Principal.

**Utility Functions:**
- `ToSerializablePrincipal(p Principal) SerializablePrincipal` - Converts Principal
- `SerializePrincipal(p Principal) (string, error)` - Serializes to JSON string
- `DeserializePrincipalFields(jsonStr string) (*SerializablePrincipal, error)` - Deserializes from JSON
- `DeserializePrincipal(jsonStr string) (Principal, error)` - Deserializes to Principal

#### ReconstructedPrincipal

```go
type ReconstructedPrincipal struct {
    // internal fields
}
```

Principal implementation from deserialized data.

**Constructor Functions:**
- `NewReconstructedPrincipal(fields SerializablePrincipal) *ReconstructedPrincipal`

**Note:** ReconstructedPrincipal has limited functionality - `CustomClaim()` and `Claims()` return nil/empty values.

### Functions

#### NewClaim

```go
func NewClaim(name, value string) Claim
```

Creates a new Claim with the specified name and value.

## Package: jwtkit

### Interfaces

#### Signer

```go
type Signer interface {
    CreateToken(principal claims.Principal, ttl time.Duration) (string, error)
}
```

Interface for creating JWT tokens from Principals.

#### Validator

```go
type Validator interface {
    Validate(tokenStr string) (claims.Principal, error)
}
```

Interface for validating JWT tokens and extracting Principals.

### Types

#### HMAC256Signer

```go
type HMAC256Signer struct {
    Secret []byte
}
```

Signer implementation using HMAC-SHA256.

**Methods:**
- `CreateToken(principal claims.Principal, ttl time.Duration) (string, error)`

#### HMAC256Validator

```go
type HMAC256Validator struct {
    Secret []byte
}
```

Validator implementation using HMAC-SHA256.

**Methods:**
- `Validate(tokenStr string) (claims.Principal, error)`

#### RSASigner

```go
type RSASigner struct {
    PrivateKey *rsa.PrivateKey
}
```

Signer implementation using RSA-SHA256.

**Methods:**
- `CreateToken(principal claims.Principal, ttl time.Duration) (string, error)`

#### RSAValidator

```go
type RSAValidator struct {
    PublicKey *rsa.PublicKey
}
```

Validator implementation using RSA-SHA256.

**Methods:**
- `Validate(tokenStr string) (claims.Principal, error)`

### Functions

#### Key Loading Functions

```go
func LoadPrivateKey(path string) (*rsa.PrivateKey, error)
```

Loads an RSA private key from a PEM file.

```go
func LoadPublicKey(path string) (*rsa.PublicKey, error)
```

Loads an RSA public key from a PEM file.

#### Conversion Functions

```go
func ToMapClaims(principal claims.Principal, ttl time.Duration) jwt.MapClaims
```

Converts a Principal and TTL to jwt.MapClaims for token creation.

**Behavior:**
- Converts timing claims (exp, nbf, iat) to float64
- Converts array claims (roles, scopes) to []string
- Converts other claims to string
- Injects 'exp' claim if not present and TTL > 0

```go
func FromMapClaims(raw jwt.MapClaims) claims.Principal
```

Converts jwt.MapClaims to a Principal.

**Behavior:**
- Converts all values to strings using fmt.Sprint
- Handles []interface{} as comma-separated strings
- Creates ClaimSet with all claims

```go
func ValidateStandardClaims(claims jwt.MapClaims) error
```

Validates exp, nbf, and iat claims in jwt.MapClaims.

**Validation Rules:**
- 'exp' claim is required and must be in the future
- 'nbf' claim (if present) must be in the past
- 'iat' claim (if present) must be in the past

## Usage Examples

### Basic ClaimSet Usage

```go
// Create and populate ClaimSet
cs := claims.NewClaimsSet("user123").
    SetIssuer("myapp").
    SetEmail("user@example.com").
    SetExpiration(time.Now().Add(time.Hour).Unix()).
    SetRoles("admin", "user")

// Access claims
subject := cs.Subject()                    // "user123"
email := cs.Email()                        // "user@example.com" 
roles := cs.Roles()                        // ["admin", "user"]
exp := cs.ExpirationTime()                 // Unix timestamp

// Custom claims
cs.Set("department", "engineering")
dept := cs.CustomClaimValue("department")  // "engineering"
```

### Claim Type Conversions

```go
// Create claims with different types
ageClaim := claims.NewClaim("age", "25")
activeClaim := claims.NewClaim("active", "true")
balanceClaim := claims.NewClaim("balance", "1234.56")

// Convert to appropriate types
age, ok := ageClaim.IntValue()           // 25, true
isActive, ok := activeClaim.BoolValue()  // true, true
balance, ok := balanceClaim.Float64Value() // 1234.56, true

// Handle array values
rolesClaim := claims.NewClaim("roles", "admin,user,guest")
roles := rolesClaim.Values(",")          // ["admin", "user", "guest"]
```

### JWT Integration

```go
// Create principal
cs := claims.NewClaimsSet("user123").SetEmail("user@example.com")
principal := claims.NewPrincipal(cs)

// HMAC signing
signer := &jwtkit.HMAC256Signer{Secret: []byte("secret")}
token, err := signer.CreateToken(principal, 1*time.Hour)

// HMAC validation
validator := &jwtkit.HMAC256Validator{Secret: []byte("secret")}
validatedPrincipal, err := validator.Validate(token)
```

### Principal Serialization

```go
// Serialize principal
principal := claims.NewPrincipal(claimSet)
jsonStr, err := claims.SerializePrincipal(principal)

// Deserialize principal
reconstructed, err := claims.DeserializePrincipal(jsonStr)

// Note: reconstructed principals have limitations
subject := reconstructed.Subject()        // Works
customClaim := reconstructed.CustomClaim("foo") // Returns nil claim
```

## Error Handling

### Common Error Patterns

```go
// Claim conversion errors
value, ok := claim.IntValue()
if !ok {
    // Handle conversion failure
}

// JWT validation errors
principal, err := validator.Validate(token)
if err != nil {
    if strings.Contains(err.Error(), "expired") {
        // Handle expired token
    } else if strings.Contains(err.Error(), "signature") {
        // Handle signature error
    }
    // Handle other errors
}

// Key loading errors
privateKey, err := jwtkit.LoadPrivateKey("key.pem")
if err != nil {
    // Handle file not found, invalid format, etc.
}
```

### Best Practices

1. **Always check conversion results**: Use the boolean return value from type conversion methods
2. **Handle JWT validation errors appropriately**: Different error types require different responses
3. **Use deep copies when needed**: `principal.Claims()` returns a copy for safe modification
4. **Validate custom claims**: Check required custom claims after JWT validation
5. **Set reasonable TTLs**: Balance security and user experience for token expiration