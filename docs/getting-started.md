# Getting started

## Install

```bash
go get github.com/fgrzl/claims
```

## Build a principal

```go
cs := claims.NewClaimsSet("user123").
    SetIssuer("myapp").
    SetEmail("user@example.com").
    SetRoles("admin", "user")

principal := claims.NewPrincipal(cs)
```

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

## Custom claims

```go
cs.Set("department", "engineering")
dept := principal.CustomClaimValue("department")
```

## Next steps

- [API reference](api-reference.md)
- [JWT integration](jwt-integration.md) — RSA, key files, error handling
