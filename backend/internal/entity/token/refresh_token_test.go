package token

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewRefreshToken(t *testing.T) {
	id := uuid.New()
	aid := uuid.New()
	exp := time.Now().Add(24 * time.Hour)

	rt := NewRefreshToken(id, aid, "hash123", exp, false, false)

	if rt.ID() != id || rt.AccessTokenID() != aid {
		t.Error("IDs mismatch")
	}
	if rt.TokenHash() != "hash123" {
		t.Error("TokenHash mismatch")
	}
	if rt.Revoked() || rt.Rotated() {
		t.Error("Revoked/Rotated should be false")
	}
}
