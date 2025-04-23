package main

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	AllowedPaths []string
	jwt.RegisteredClaims
}

func ParseJWT(jwtKey []byte, authHeader string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(authHeader, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrTokenUnverifiable
		}
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("Invalid token")
	}
	return token.Claims.(*Claims), nil
}

func GenerateJWT(jwtKey []byte, allowedPaths []string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		AllowedPaths: allowedPaths,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "YAPILY_EXJOBB_APIGATEWAY",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}
