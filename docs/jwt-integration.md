# JWT Integration Guide

This guide covers how to use the Claims library with JWT tokens using the `jwtkit` package.

## Overview

The `jwtkit` package provides:
- **Signers**: Create JWT tokens from Principals
- **Validators**: Extract Principals from JWT tokens
- **Utilities**: Convert between Claims and jwt.MapClaims

## Supported Algorithms

### HMAC-SHA256 (HS256)
- **Use case**: Single application or service
- **Key management**: Shared secret
- **Performance**: Fast
- **Security**: Symmetric key

### RSA-SHA256 (RS256)
- **Use case**: Distributed systems, microservices
- **Key management**: Public/private key pair
- **Performance**: Slower than HMAC
- **Security**: Asymmetric key

## HMAC256 Usage

### Basic Usage

```go
package main

import (
    "time"
    "github.com/fgrzl/claims"
    "github.com/fgrzl/claims/jwtkit"
)

func main() {
    secret := []byte("your-256-bit-secret")
    
    // Create signer and validator
    signer := &jwtkit.HMAC256Signer{Secret: secret}
    validator := &jwtkit.HMAC256Validator{Secret: secret}
    
    // Create a principal
    cs := claims.NewClaimsSet("user123").
        SetIssuer("myapp").
        SetEmail("user@example.com")
    principal := claims.NewPrincipal(cs)
    
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
    
    fmt.Println("Subject:", validatedPrincipal.Subject())
}
```

### Secret Management

```go
// Load from environment
secret := []byte(os.Getenv("JWT_SECRET"))

// Generate random secret (for development)
secret := make([]byte, 32)
_, err := rand.Read(secret)
if err != nil {
    panic(err)
}

// Use crypto/subtle for comparison
func secretsEqual(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}
```

## RSA Usage

### Key Generation

Generate RSA key pair using OpenSSL:

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -outform PEM -out public.pem
```

### Basic Usage

```go
package main

import (
    "github.com/fgrzl/claims"
    "github.com/fgrzl/claims/jwtkit"
)

func main() {
    // Load keys
    privateKey, err := jwtkit.LoadPrivateKey("private.pem")
    if err != nil {
        panic(err)
    }
    
    publicKey, err := jwtkit.LoadPublicKey("public.pem")
    if err != nil {
        panic(err)
    }
    
    // Create signer and validator
    signer := &jwtkit.RSASigner{PrivateKey: privateKey}
    validator := &jwtkit.RSAValidator{PublicKey: publicKey}
    
    // Use same as HMAC example...
}
```

### In-Memory Key Generation

```go
import (
    "crypto/rand"
    "crypto/rsa"
)

func generateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }
    return privateKey, &privateKey.PublicKey, nil
}
```

## Token Validation

### Standard Claims Validation

The library automatically validates:
- **exp**: Token expiration time
- **nbf**: Not before time (optional)
- **iat**: Issued at time (optional)

```go
validator := &jwtkit.HMAC256Validator{Secret: secret}
principal, err := validator.Validate(token)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "expired"):
        // Handle expired token
        return handleExpiredToken()
    case strings.Contains(err.Error(), "not valid yet"):
        // Handle not-yet-valid token
        return handlePrematureToken()
    default:
        // Handle other validation errors
        return handleInvalidToken(err)
    }
}
```

### Custom Validation

```go
func validateCustomClaims(principal claims.Principal) error {
    // Check required custom claims
    if principal.CustomClaimValue("tenant_id") == "" {
        return errors.New("missing tenant_id claim")
    }
    
    // Validate roles
    roles := principal.Roles()
    if len(roles) == 0 {
        return errors.New("user must have at least one role")
    }
    
    return nil
}

// Use in your validation flow
principal, err := validator.Validate(token)
if err != nil {
    return err
}

if err := validateCustomClaims(principal); err != nil {
    return err
}
```

## Advanced Usage

### TTL Handling

```go
// TTL affects token expiration
var ttl time.Duration

switch userType {
case "admin":
    ttl = 8 * time.Hour
case "user":
    ttl = 2 * time.Hour
case "guest":
    ttl = 30 * time.Minute
}

token, err := signer.CreateToken(principal, ttl)
```

### Token Refresh

```go
func refreshToken(oldToken string, validator jwtkit.Validator, signer jwtkit.Signer) (string, error) {
    // Validate existing token (might be expired)
    principal, err := validator.Validate(oldToken)
    if err != nil {
        // Check if error is due to expiration
        if !strings.Contains(err.Error(), "expired") {
            return "", err // Other validation error
        }
        // Continue with refresh even if expired
    }
    
    // Create new token with fresh expiration
    return signer.CreateToken(principal, 1*time.Hour)
}
```

### Multiple Audiences

```go
cs := claims.NewClaimsSet("user123").
    SetAudience("api.example.com,admin.example.com")

principal := claims.NewPrincipal(cs)
audiences := principal.Audience() // ["api.example.com", "admin.example.com"]

// Validate specific audience
func hasAudience(principal claims.Principal, requiredAud string) bool {
    for _, aud := range principal.Audience() {
        if aud == requiredAud {
            return true
        }
    }
    return false
}
```

## Error Handling

### Common Errors

```go
principal, err := validator.Validate(token)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "token is expired"):
        // Token has expired
        return ErrTokenExpired
        
    case strings.Contains(err.Error(), "token not valid yet"):
        // Token's nbf claim is in the future
        return ErrTokenNotValidYet
        
    case strings.Contains(err.Error(), "signature is invalid"):
        // Token signature doesn't match
        return ErrInvalidSignature
        
    case strings.Contains(err.Error(), "failed to parse token"):
        // Malformed token
        return ErrMalformedToken
        
    default:
        // Other validation error
        return fmt.Errorf("token validation failed: %w", err)
    }
}
```

### Production Error Handling

```go
type TokenError struct {
    Code    string
    Message string
    Cause   error
}

func (e *TokenError) Error() string {
    return e.Message
}

func validateToken(tokenStr string, validator jwtkit.Validator) (claims.Principal, *TokenError) {
    principal, err := validator.Validate(tokenStr)
    if err != nil {
        if strings.Contains(err.Error(), "expired") {
            return nil, &TokenError{
                Code:    "TOKEN_EXPIRED",
                Message: "Token has expired",
                Cause:   err,
            }
        }
        
        return nil, &TokenError{
            Code:    "TOKEN_INVALID",
            Message: "Invalid token",
            Cause:   err,
        }
    }
    
    return principal, nil
}
```

## Best Practices

### Key Management
1. **Rotate keys regularly**: Implement key rotation for long-running services
2. **Use environment variables**: Never hardcode secrets in source code
3. **Separate keys by environment**: Use different keys for dev/staging/prod

### Performance
1. **Reuse signer/validator instances**: They're thread-safe
2. **Cache public keys**: For RSA validation in high-throughput scenarios
3. **Use connection pooling**: For key fetching from remote sources

### Security
1. **Validate all timing claims**: Always check exp, nbf, iat
2. **Use HTTPS only**: Never send JWTs over unencrypted connections
3. **Implement proper CORS**: Restrict origins that can access tokens
4. **Short expiration times**: Use refresh tokens for longer sessions

### Monitoring
```go
func instrumentedValidate(validator jwtkit.Validator, token string) (claims.Principal, error) {
    start := time.Now()
    principal, err := validator.Validate(token)
    duration := time.Since(start)
    
    // Log metrics
    if err != nil {
        metrics.Counter("jwt.validation.errors").Inc()
        log.Printf("JWT validation failed in %v: %v", duration, err)
    } else {
        metrics.Counter("jwt.validation.success").Inc()
        metrics.Histogram("jwt.validation.duration").Observe(duration.Seconds())
    }
    
    return principal, err
}
```