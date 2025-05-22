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
		mapClaims[k] = v.Value()
	}

	// Inject 'exp' if not already set
	if _, ok := mapClaims["exp"]; !ok && ttl > 0 {
		mapClaims["exp"] = time.Now().Add(ttl).Unix()
	}
	return mapClaims
}

func FromMapClaims(raw jwt.MapClaims) claims.Principal {
	claimsMap := make(map[string]claims.Claim, len(raw))

	for k, v := range raw {
		switch val := v.(type) {
		case string:
			claimsMap[k] = claims.NewClaim(k, val)
		case float64:
			claimsMap[k] = claims.NewClaim(k, fmt.Sprintf("%v", val))
		case []interface{}:
			strs := make([]string, 0, len(val))
			for _, item := range val {
				strs = append(strs, fmt.Sprint(item))
			}
			claimsMap[k] = claims.NewClaim(k, strings.Join(strs, ","))
		case interface{}:
			claimsMap[k] = claims.NewClaim(k, fmt.Sprint(val))
		default:
			// unknown type, skip
		}
	}

	p := claims.NewClaimsPrincipal(claimsMap)
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
