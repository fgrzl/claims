package jwtkit

import (
	"fmt"
	"strings"
	"time"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
)

// ToMapClaims converts a Principal and TTL to jwt.MapClaims for token creation.
func ToMapClaims(principal claims.Principal, ttl time.Duration) jwt.MapClaims {
	mapClaims := jwt.MapClaims{}

	claimSet := principal.Claims()
	claimSet.Range(func(k string, v claims.Claim) {
		switch k {
		case "exp", "nbf", "iat":
			if floatVal, ok := v.Float64Value(); ok {
				mapClaims[k] = floatVal
			}
		case "roles", "scopes":
			mapClaims[k] = v.Values(",")

		default:
			mapClaims[k] = v.Value()
		}
	})

	// Inject 'exp' if not already set and TTL is positive
	if _, ok := mapClaims["exp"]; !ok && ttl > 0 {
		mapClaims["exp"] = float64(time.Now().Add(ttl).Unix())
	}

	return mapClaims
}

// FromMapClaims converts jwt.MapClaims to a Principal.
func FromMapClaims(raw jwt.MapClaims) claims.Principal {
	cs := claims.MakeClaimsSet(len(raw))

	for k, v := range raw {
		switch val := v.(type) {
		case string:
			cs.Set(k, val)
		case float64:
			cs.Set(k, fmt.Sprintf("%v", val))
		case []any:
			strs := make([]string, 0, len(val))
			for _, item := range val {
				strs = append(strs, fmt.Sprint(item))
			}
			cs.Set(k, strings.Join(strs, ","))
		default:
			cs.Set(k, fmt.Sprint(val))
		}
	}

	return claims.NewPrincipal(cs)
}

// ValidateStandardClaims validates exp, nbf, and iat claims inside jwt.MapClaims.
// It returns an error if any are invalid or missing (for exp).
func ValidateStandardClaims(claims jwt.MapClaims) error {
	now := time.Now().Unix()

	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("expiration claim missing or invalid")
	}
	if now > int64(exp) {
		return fmt.Errorf("token has expired")
	}

	// Optional: "nbf" (not before)
	if nbf, ok := claims["nbf"].(float64); ok {
		if now < int64(nbf) {
			return fmt.Errorf("token not valid yet")
		}
	}

	// Optional: "iat" (issued at)
	if iat, ok := claims["iat"].(float64); ok {
		if now < int64(iat) {
			return fmt.Errorf("token issued in the future")
		}
	}

	return nil
}
