package jwtkit

import (
	"fmt"
	"strings"
	"time"

	"github.com/fgrzl/claims"
	"github.com/golang-jwt/jwt/v5"
)

func ToMapClaims(principal claims.Principal, ttl time.Duration) jwt.MapClaims {
	mapClaims := jwt.MapClaims{}

	for k, v := range principal.Claims() {
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
	}

	// Inject 'exp' if not already set and TTL is positive
	if _, ok := mapClaims["exp"]; !ok && ttl > 0 {
		mapClaims["exp"] = float64(time.Now().Add(ttl).Unix())
	}

	return mapClaims
}

func FromMapClaims(raw jwt.MapClaims) claims.Principal {
	claimSet := make(claims.ClaimSet, len(raw))

	for k, v := range raw {
		switch val := v.(type) {
		case string:
			claimSet[k] = claims.NewClaim(k, val)
		case float64:
			claimSet[k] = claims.NewClaim(k, fmt.Sprintf("%v", val))
		case []interface{}:
			strs := make([]string, 0, len(val))
			for _, item := range val {
				strs = append(strs, fmt.Sprint(item))
			}
			claimSet[k] = claims.NewClaim(k, strings.Join(strs, ","))
		case interface{}:
			claimSet[k] = claims.NewClaim(k, fmt.Sprint(val))
		default:
			// unknown type, skip
		}
	}

	p := claims.NewPrincipal(claimSet, nil)
	return p
}

// ValidateStandardClaims validates exp, nbf, and iat claims inside jwt.MapClaims.
// It returns an error if any are invalid or missing (for exp).
func ValidateStandardClaims(claims jwt.MapClaims) error {
	now := time.Now().Unix()

	// Require and check "exp"
	if exp, ok := claims["exp"].(float64); ok {
		if now > int64(exp) {
			return fmt.Errorf("token has expired")
		}
	} else {
		return fmt.Errorf("expiration claim missing or invalid")
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
