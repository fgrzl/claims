# Getting started

## Install

```bash
go get github.com/fgrzl/claims
```

## Build a principal

```go
import (
    "time"

    "github.com/fgrzl/claims"
    "github.com/fgrzl/claims/jwtkit"
)

cs := claims.NewClaimsSet("user123").
    SetIssuer("myapp").
    SetEmail("user@example.com").
    SetRoles("admin", "user").
    Set("department", "engineering")

principal := claims.NewPrincipal(cs)
```

Set custom claims on `ClaimSet` **before** `NewPrincipal` — the principal holds a copy; mutating `cs` afterward does not change the principal.

## Sign a JWT (HMAC)

```go
secret := []byte(os.Getenv("JWT_SECRET"))
signer := &jwtkit.HMAC256Signer{Secret: secret}

token, err := signer.CreateToken(principal, time.Hour)
```

## Validate

```go
validator := &jwtkit.HMAC256Validator{Secret: secret}
validated, err := validator.Validate(token)
if err != nil {
    return err
}
_ = validated.Subject()
```

## Custom claims on principal

```go
dept := principal.CustomClaimValue("department")
```

## Next steps

- [API reference](api-reference.md)
- [JWT integration](jwt-integration.md) — RSA, key files, error handling
