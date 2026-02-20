#!/bin/bash
# Step4 E2E 用 seed 実行スクリプト
# 使い方: ./scripts/seed_step4.sh [password] [redirect_uri]
# 例: ./scripts/seed_step4.sh password123 http://localhost:5173/callback

set -e
cd "$(dirname "$0")/.."

PASSWORD="${1:-password123}"
REDIRECT_URI="${2:-http://localhost:5173/callback}"

echo "=== Step4 seed ==="
echo "password: $PASSWORD"
echo "redirect_uri: $REDIRECT_URI"

# bcrypt 生成
USER_PASSWORD_HASH=$(go run ./scripts/hash_user_password "$PASSWORD")
# 固定 UUID で E2E 用 client（authorize URL をコピペしやすい）
CLIENT_ID="11111111-1111-1111-1111-111111111111"

echo "client_id: $CLIENT_ID"
echo ""

# DB 接続情報（.env から読み込み）
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"
DB_NAME="${DB_NAME:-oauth_server}"

# .env があれば読み込み
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

export PGPASSWORD="$DB_PASSWORD"

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 <<EOF
-- users（固定 ID で upsert）
INSERT INTO users (id, email, username, password_hash, email_verified, status, created_at, updated_at)
VALUES (
  '00000000-0000-0000-0000-000000000001'::uuid,
  'test@example.com',
  'testuser',
  '$USER_PASSWORD_HASH',
  false,
  'active',
  NOW(),
  NOW()
)
ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();

-- clients（client_id = id、固定 UUID で upsert）
INSERT INTO clients (id, client_secret_hash, redirect_uris, allowed_scopes)
VALUES (
  '$CLIENT_ID'::uuid,
  '',
  '$REDIRECT_URI',
  'openid profile'
)
ON CONFLICT (id) DO UPDATE SET
  redirect_uris = EXCLUDED.redirect_uris,
  allowed_scopes = EXCLUDED.allowed_scopes;
EOF

echo ""
echo "✅ seed 完了"
echo "client_id: $CLIENT_ID"
echo "username: testuser"
echo "password: $PASSWORD"
echo "redirect_uri: $REDIRECT_URI"
