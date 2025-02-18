package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	// Setup test data
	userID := uuid.New() // Create a new UUID for testing
	secret := "your-test-secret"
	duration := time.Minute * 1 // 1 minute expiration

	// Test cases could include:
	t.Run("valid token", func(t *testing.T) {
		// 1. Create a token
		token, err := MakeJWT(userID, secret, duration)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		// 2. Validate the token
		gotID, err := ValidateJWT(token, secret)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		// 3. Check if we got back the same UUID
		if gotID != userID {
			t.Errorf("got user ID %v, want %v", gotID, userID)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		duration := -time.Minute * 1
		token, err := MakeJWT(userID, secret, duration)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		//try to validate - should fail
		_, err = ValidateJWT(token, secret)
		if err == nil {
			t.Fatal("expected error for expired token, got nil")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		duration := time.Minute * 1
		secret1 := "wrong-test-secret"
		token, err := MakeJWT(userID, secret, duration)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}
		// 2. Validate token

		_, err = ValidateJWT(token, secret1)
		if err == nil {
			t.Fatalf("expected error for wrong secret, got nil")
		}

	})
}
