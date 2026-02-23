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
		uuid.New(),
		"hash",
		"challenge",
		CodeChallengeMethodS256,
		"https://example.com/callback",
		"openid",
		"",
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
		uuid.New(),
		"hash",
		"challenge",
		CodeChallengeMethodS256,
		"https://example.com/callback",
		"openid",
		"",
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
		uuid.New(),
		"hash",
		"challenge",
		CodeChallengeMethodS256,
		"https://example.com/callback",
		"openid",
		"",
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

func TestReconstruct(t *testing.T) {
	id := uuid.New()
	uid := uuid.New()
	cid := uuid.New()
	sid := uuid.New()
	expiresAt := time.Now().Add(time.Hour)
	createdAt := time.Now()

	code := Reconstruct(id, uid, cid, sid, "hash", "challenge", CodeChallengeMethodS256, "https://example.com/cb", "openid", "n", expiresAt, true, createdAt)

	if code.ID() != id || code.UserID() != uid || code.ClientID() != cid || code.SessionID() != sid {
		t.Error("Reconstruct: IDs mismatch")
	}
	if code.CodeHash() != "hash" || code.CodeChallenge() != "challenge" || code.CodeChallengeMethod() != CodeChallengeMethodS256 {
		t.Error("Reconstruct: PKCE fields mismatch")
	}
	if code.RedirectURI() != "https://example.com/cb" || code.Scopes() != "openid" || code.Nonce() != "n" {
		t.Error("Reconstruct: URI/scope/nonce mismatch")
	}
	if !code.IsConsumed() {
		t.Error("Reconstruct: consumed should be true")
	}
}
