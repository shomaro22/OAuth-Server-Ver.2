package token

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewAccessToken(t *testing.T) {
	id := uuid.New()
	uid := uuid.New()
	cid := uuid.New()
	sid := uuid.New()
	now := time.Now()
	exp := now.Add(time.Hour)

	at := NewAccessToken(id, uid, cid, sid, "jti-1", "openid", now, exp, false)

	if at.ID() != id || at.UserID() != uid || at.ClientID() != cid || at.SessionID() != sid {
		t.Error("IDs mismatch")
	}
	if at.TokenJTI() != "jti-1" || at.Scopes() != "openid" {
		t.Error("TokenJTI/Scopes mismatch")
	}
	if at.Revoked() {
		t.Error("Revoked should be false")
	}
}
