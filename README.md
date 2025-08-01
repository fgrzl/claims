[![ci](https://github.com/fgrzl/claims/actions/workflows/ci.yml/badge.svg)](https://github.com/fgrzl/claims/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/fgrzl/claims/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/fgrzl/claims/actions/workflows/dependabot/dependabot-updates)

# Claims

A flexible and type-safe Go library for working with JWT claims and authenticated identities.

## Features

- **Type-safe claim access** - Convert claims to various Go types with validation
- **Immutable Principals** - Thread-safe authenticated identity representation  
- **JWT integration** - Built-in support for HMAC-SHA256 and RSA-SHA256 signing/validation
- **Flexible claim building** - Multiple patterns for constructing claim sets
- **Serialization support** - JSON serialization for message passing and caching

## Quick Start

```go
go get github.com/fgrzl/claims
```

### Basic Usage

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
    
    // Create an immutable principal
    principal := claims.NewPrincipal(cs)
    
    // Access claims with type safety
    fmt.Println("Subject:", principal.Subject())         // "user123"
    fmt.Println("Email:", principal.Email())             // "user@example.com"  
    fmt.Println("Roles:", principal.Roles())             // ["admin", "user"]
    
    // Create and validate JWT tokens
    secret := []byte("my-secret-key")
    signer := &jwtkit.HMAC256Signer{Secret: secret}
    validator := &jwtkit.HMAC256Validator{Secret: secret}
    
    // Sign
    token, err := signer.CreateToken(principal, 1*time.Hour)
    if err != nil {
        panic(err)
    }
    
    // Validate  
    validatedPrincipal, err := validator.Validate(token)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Validated Subject:", validatedPrincipal.Subject())
}
```

## Core Concepts

### Claims
Individual pieces of information with type conversion support:

```go
claim := claims.NewClaim("age", "25")
age, ok := claim.IntValue()        // 25, true
ageStr := claim.Value()           // "25"
```

### ClaimSets
Collections of claims with fluent builder pattern:

```go
cs := claims.NewClaimsSet("user123").
    SetIssuer("myapp").
    SetExpiration(time.Now().Add(time.Hour).Unix()).
    SetRoles("admin", "user").
    Set("department", "engineering")  // Custom claims
```

### Principals  
Immutable authenticated identities:

```go
principal := claims.NewPrincipal(cs)

// Standard JWT claims
subject := principal.Subject()
roles := principal.Roles()

// Custom claims  
dept := principal.CustomClaimValue("department")
```

## JWT Integration

### HMAC-SHA256 (Symmetric)

```go
secret := []byte("your-secret-key")

signer := &jwtkit.HMAC256Signer{Secret: secret}
validator := &jwtkit.HMAC256Validator{Secret: secret}

token, _ := signer.CreateToken(principal, 1*time.Hour)
validatedPrincipal, _ := validator.Validate(token)
```

### RSA-SHA256 (Asymmetric)

```go
privateKey, _ := jwtkit.LoadPrivateKey("private.pem")
publicKey, _ := jwtkit.LoadPublicKey("public.pem")

signer := &jwtkit.RSASigner{PrivateKey: privateKey}
validator := &jwtkit.RSAValidator{PublicKey: publicKey}

token, _ := signer.CreateToken(principal, 1*time.Hour)
validatedPrincipal, _ := validator.Validate(token)
```

## Advanced Features

### Type Conversions

```go
claim := claims.NewClaim("count", "42")

// Safe type conversions with validation
intVal, ok := claim.IntValue()      // 42, true
floatVal, ok := claim.Float64Value() // 42.0, true
boolVal, ok := claim.BoolValue()    // false, false

// Array handling
rolesClaim := claims.NewClaim("roles", "admin,user,guest")
roles := rolesClaim.Values(",")     // ["admin", "user", "guest"]
```

### Principal Serialization

```go
// For message passing or caching
jsonStr, err := claims.SerializePrincipal(principal)
reconstructed, err := claims.DeserializePrincipal(jsonStr)
```

### Incremental Building

```go
// Using ClaimList for dynamic construction
list := claims.NewClaimsList("sub", "user123")

if userEmail != "" {
    list = list.Add("email", userEmail)
}

cs := claims.ToClaimSet(list)
principal := claims.NewPrincipal(cs)
```

## Documentation

- **[Complete Guide](docs/README.md)** - Comprehensive documentation with examples
- **[JWT Integration](docs/jwt-integration.md)** - Detailed JWT usage patterns
- **[API Reference](docs/api-reference.md)** - Complete API documentation

## Examples

### Web Authentication

```go
func authenticateHandler(w http.ResponseWriter, r *http.Request) {
    // Extract token from Authorization header
    authHeader := r.Header.Get("Authorization")
    token := strings.TrimPrefix(authHeader, "Bearer ")
    
    // Validate token
    principal, err := validator.Validate(token)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    
    // Check permissions
    if !hasRole(principal, "admin") {
        http.Error(w, "Insufficient permissions", http.StatusForbidden)
        return  
    }
    
    // Continue with authenticated request...
}

func hasRole(principal claims.Principal, requiredRole string) bool {
    for _, role := range principal.Roles() {
        if role == requiredRole {
            return true
        }
    }
    return false
}
```

### Microservice Communication

```go
// Service A: Create principal and serialize for message
principal := claims.NewPrincipal(
    claims.NewClaimsSet("user123").
        SetEmail("user@example.com").
        SetRoles("user", "admin"),
)

principalJSON, _ := claims.SerializePrincipal(principal)

// Send in message header
message := Message{
    Headers: map[string]string{
        "X-Principal": principalJSON,
    },
    Body: requestData,
}

// Service B: Deserialize principal from message  
principalJSON := message.Headers["X-Principal"]
principal, _ := claims.DeserializePrincipal(principalJSON)

// Use principal for authorization
if principal.CustomClaimValue("tenant_id") != allowedTenant {
    return errors.New("unauthorized tenant")
}
```

## Requirements

- Go 1.24.0 or later
- Dependencies managed via Go modules

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Ensure all tests pass: `go test ./...`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
