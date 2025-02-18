package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	// password gen
	passByte := []byte(password)
	userPass, err := bcrypt.GenerateFromPassword(passByte, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	passwordString := string(userPass)

	return passwordString, nil

}

func CheckPasswordHash(password, hash string) error {
	// Your code here using bcrypt.CompareHashAndPassword
	passByte := []byte(password)
	hashByte := []byte(hash)

	err := bcrypt.CompareHashAndPassword(hashByte, passByte)
	if err != nil {
		return err
	}
	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Issuer:    "chirpy",
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString([]byte(tokenSecret))

	return signedString, err
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	// ensure validity of token
	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	// Get subject (which contains stringified UUID)
	subject := claims.Subject

	// Convert string back to UUID
	userID, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in token")
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is empty")
	}
	splitHeader := strings.Split(authHeader, " ")

	if len(splitHeader) != 2 {
		return "", fmt.Errorf("invalid token format")
	}

	if splitHeader[0] != "Bearer" {
		return "", fmt.Errorf("header format is invalid")
	}

	return splitHeader[1], nil

}

func MakeRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return " ", fmt.Errorf("error generating random data")
	}
	encodedData := hex.EncodeToString(tokenBytes)

	return encodedData, nil

}
