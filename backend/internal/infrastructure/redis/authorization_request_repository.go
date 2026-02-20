package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

const keyPrefix = "auth_req:"

// AuthorizationRequestRepository は Redis による AuthorizationRequestRepository の実装。
type AuthorizationRequestRepository struct {
	client *redis.Client
}

// NewAuthorizationRequestRepository は AuthorizationRequestRepository を生成する。
func NewAuthorizationRequestRepository(client *redis.Client) *AuthorizationRequestRepository {
	return &AuthorizationRequestRepository{client: client}
}

// Save は認可リクエストを challenge に紐づけて保存する。
func (r *AuthorizationRequestRepository) Save(ctx context.Context, challenge string, req *port.StoredAuthorizationRequest, ttl time.Duration) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	key := keyPrefix + challenge
	return r.client.Set(ctx, key, b, ttl).Err()
}

// Get は challenge に紐づく認可リクエストを取得する。
func (r *AuthorizationRequestRepository) Get(ctx context.Context, challenge string) (*port.StoredAuthorizationRequest, error) {
	key := keyPrefix + challenge
	b, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}
	var req port.StoredAuthorizationRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &req, nil
}

// Delete は challenge を削除する（one-time 用）。
func (r *AuthorizationRequestRepository) Delete(ctx context.Context, challenge string) error {
	key := keyPrefix + challenge
	return r.client.Del(ctx, key).Err()
}
