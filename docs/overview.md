# Overview

The claims library models **authenticated identity** as immutable data plus optional JWT packaging.

## Core types

| Type | Role |
|------|------|
| `Claim` | Single name/value with typed accessors (`IntValue`, `BoolValue`, …) |
| `ClaimSet` | Mutable builder for standard and custom JWT claims |
| `ClaimList` | Low-allocation list builder converted to `ClaimSet` |
| `Principal` | Immutable identity used after authentication |

## Standard claims

`ClaimSet` exposes helpers for `sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`, plus app claims like email, name, roles, and scopes.

## JWT (`jwtkit`)

| Signer / validator | Use case |
|--------------------|----------|
| `HMAC256Signer` / `HMAC256Validator` | Shared secret services |
| `RSASigner` / `RSAValidator` | Public-key deployments |

See [JWT integration](jwt-integration.md) for key loading and validation patterns.

## Serialization

`SerializePrincipal` / `DeserializePrincipal` support message passing. Deserialized principals have limited mutability — prefer full `ClaimSet` reconstruction when you need custom claim writes.

## Security practices

- Set reasonable `exp` on every token
- Protect HMAC secrets and RSA private keys
- Validate tokens on every request boundary
- Prefer immutable `Principal` in handlers after validation
