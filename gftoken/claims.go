package gftoken

import "github.com/golang-jwt/jwt/v4"

type CustomClaims struct {
	Data interface{}
	jwt.RegisteredClaims
}
