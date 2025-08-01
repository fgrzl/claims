# Claims Library Documentation

The Claims library provides a flexible and type-safe way to work with JWT claims in Go applications.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
- [JWT Integration](#jwt-integration)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Quick Start

```go
package main

import (
    "fmt"
    "time"
    
    "github.com/fgrzl/claims"
    "github.com/fgrzl/claims/jwtkit"
)

func main() {
    // Create a claim set
    cs := claims.NewClaimsSet("user123").
        SetIssuer("myapp").
        SetEmail("user@example.com").
        SetRoles("admin", "user")
    
    // Create a principal
    principal := claims.NewPrincipal(cs)
    
    // Use with JWT
    secret := []byte("my-secret-key")
    signer := &jwtkit.HMAC256Signer{Secret: secret}
    token, _ := signer.CreateToken(principal, 1*time.Hour)
    
    fmt.Println("JWT Token:", token)
}
```

## Core Concepts

### Claim

A `Claim` represents a single piece of information with a name and value. Claims can be converted to various Go types:

```go
claim := claims.NewClaim("age", "25")

age, ok := claim.IntValue()        // 25, true
ageStr := claim.Value()           // "25"
```

### ClaimSet

A `ClaimSet` is a collection of claims that provides type-safe access to standard JWT claims:

```go
cs := claims.NewClaimsSet("user123").
    SetIssuer("myapp").
    SetExpiration(time.Now().Add(time.Hour).Unix()).
    SetRoles("admin", "user")

subject := cs.Subject()           // "user123"
roles := cs.Roles()              // ["admin", "user"]
```

### ClaimList

A `ClaimList` provides a builder pattern for creating collections of claims:

```go
list := claims.NewClaimsList("sub", "user123").
    Add("email", "user@example.com").
    Add("roles", "admin,user")

claimSet := claims.ToClaimSet(list)
```

### Principal

A `Principal` represents an authenticated identity with immutable access to claims:

```go
principal := claims.NewPrincipal(claimSet)

// Standard claims
subject := principal.Subject()
email := principal.Email()
roles := principal.Roles()

// Custom claims
department := principal.CustomClaimValue("department")
```

## API Reference

### Standard JWT Claims

The library provides type-safe access to standard JWT claims:

- `Subject()` - The subject (user ID) of the token
- `Issuer()` - The entity that issued the token
- `Audience()` - The intended audience(s) 
- `ExpirationTime()` - Token expiration time (Unix timestamp)
- `NotBefore()` - Time before which token is invalid
- `IssuedAt()` - Time when token was issued
- `JWTI()` - Unique token identifier

### Custom Claims

Access custom claims using:

- `CustomClaim(name)` - Returns a `Claim` interface
- `CustomClaimValue(name)` - Returns the string value directly

### Type Conversions

Claims can be converted to various types:

```go
claim := claims.NewClaim("count", "42")

intVal, ok := claim.IntValue()      // 42, true
int32Val, ok := claim.Int32Value()  // 42, true  
int64Val, ok := claim.Int64Value()  // 42, true
floatVal, ok := claim.Float64Value() // 42.0, true
boolVal, ok := claim.BoolValue()    // false, false (not a bool)

// Split values
rolesStr := "admin,user,guest"
rolesClaim := claims.NewClaim("roles", rolesStr)
roles := rolesClaim.Values(",")     // ["admin", "user", "guest"]
```

## JWT Integration

The `jwtkit` package provides JWT signing and validation:

### HMAC256 (Symmetric)

```go
secret := []byte("my-secret-key")

// Signing
signer := &jwtkit.HMAC256Signer{Secret: secret}
token, err := signer.CreateToken(principal, 1*time.Hour)

// Validation
validator := &jwtkit.HMAC256Validator{Secret: secret}
validatedPrincipal, err := validator.Validate(token)
```

### RSA (Asymmetric)

```go
// Load keys from PEM files
privateKey, err := jwtkit.LoadPrivateKey("private.pem")
publicKey, err := jwtkit.LoadPublicKey("public.pem")

// Signing
signer := &jwtkit.RSASigner{PrivateKey: privateKey}
token, err := signer.CreateToken(principal, 1*time.Hour)

// Validation
validator := &jwtkit.RSAValidator{PublicKey: publicKey}
validatedPrincipal, err := validator.Validate(token)
```

## Examples

### Building Complex Claims

```go
// Create a complex principal with various claims
cs := claims.NewClaimsSet("employee123").
    SetIssuer("company-auth").
    SetAudience("api.company.com").
    SetEmail("john.doe@company.com").
    SetName("John Doe").
    SetExpiration(time.Now().Add(8*time.Hour).Unix()).
    SetRoles("employee", "manager").
    SetScopes("read", "write", "admin").
    Set("department", "engineering").
    Set("employee_id", "E12345").
    Set("clearance_level", "3")

principal := claims.NewPrincipal(cs)
```

### Principal Serialization

For message passing or caching:

```go
// Serialize to JSON
jsonStr, err := claims.SerializePrincipal(principal)

// Deserialize from JSON
reconstructedPrincipal, err := claims.DeserializePrincipal(jsonStr)

// Note: Reconstructed principals have limited functionality
// (no custom claims access, no underlying ClaimSet)
```

### Working with Claim Lists

```go
// Build incrementally
list := claims.NewClaimsList("sub", "user123")

if userEmail != "" {
    list = list.Add("email", userEmail)
}

if len(userRoles) > 0 {
    list = list.Add("roles", strings.Join(userRoles, ","))
}

// Convert to ClaimSet for full functionality
cs := claims.ToClaimSet(list)
principal := claims.NewPrincipal(cs)
```

### Array Claims

```go
cs := claims.NewClaimsSet("user123")

// Set multiple roles
cs.SetRoles("user", "admin", "guest")

// Append additional roles (deduplicates automatically)
cs.AppendRoles("moderator", "user") // Won't duplicate "user"

roles := cs.Roles() // ["admin", "guest", "moderator", "user"] (sorted)
```

## Best Practices

### Security

1. **Use appropriate key sizes**: RSA keys should be at least 2048 bits
2. **Protect secrets**: Never hardcode HMAC secrets in source code
3. **Set expiration times**: Always include reasonable token expiration
4. **Validate claims**: Always validate exp, nbf, and iat claims

### Performance

1. **Reuse signers/validators**: Create once, use many times
2. **Use ClaimSet for frequent access**: More efficient than ClaimList for lookups
3. **Avoid unnecessary conversions**: Access claims in their native format when possible

### Error Handling

```go
// Always check errors from JWT operations
token, err := signer.CreateToken(principal, ttl)
if err != nil {
    log.Printf("Failed to create token: %v", err)
    return err
}

// Validate tokens with proper error handling
principal, err := validator.Validate(tokenString)
if err != nil {
    if strings.Contains(err.Error(), "expired") {
        return ErrTokenExpired
    }
    return ErrInvalidToken
}
```

### Memory Management

```go
// Principal.Claims() returns a deep copy - safe for modification
claimsCopy := principal.Claims()
claimsCopy.SetSubject("modified") // Won't affect original principal

// ClaimSet operations are fluent and modify the instance
cs := claims.NewClaimsSet("user123").
    SetEmail("user@example.com").  // Returns same instance
    SetRoles("admin")              // Returns same instance
```