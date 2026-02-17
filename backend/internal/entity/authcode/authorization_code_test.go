package authcode

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthorizationCode_IsExpired(t *testing.T) {
	expiresAt := time.Now().Add(-time.Minute)
	code := New(
		uuid.New(),
		uuid.New(),
		"hash",
		"challenge",
		CodeChallengeMethodS256,
		"https://example.com/callback",
		"openid",
		expiresAt,
	)

	if !code.IsExpired(time.Now()) {
		t.Error("IsExpired: expected true for expired code")
	}
}

func TestAuthorizationCode_IsConsumed(t *testing.T) {
	code := New(
		uuid.New(),
		uuid.New(),
		"hash",
		"challenge",
		CodeChallengeMethodS256,
		"https://example.com/callback",
		"openid",
		time.Now().Add(time.Minute),
	)

	if code.IsConsumed() {
		t.Error("IsConsumed: expected false for new code")
	}

	code.Consume()
	if !code.IsConsumed() {
		t.Error("IsConsumed: expected true after Consume")
	}
}

func TestAuthorizationCode_IsValid(t *testing.T) {
	code := New(
		uuid.New(),
		uuid.New(),
		"hash",
		"challenge",
		CodeChallengeMethodS256,
		"https://example.com/callback",
		"openid",
		time.Now().Add(time.Minute),
	)

	if !code.IsValid(time.Now()) {
		t.Error("IsValid: expected true for valid code")
	}

	code.Consume()
	if code.IsValid(time.Now()) {
		t.Error("IsValid: expected false after Consume")
	}
}
