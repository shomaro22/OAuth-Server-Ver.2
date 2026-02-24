#!/bin/bash
# マイグレーション一括実行（000〜005 を順番に適用）
# 使い方: ./scripts/migrate.sh
# 前提: .env に DB_HOST, DB_USER, DB_PASSWORD, DB_NAME を設定

set -e
cd "$(dirname "$0")/.."

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-auth_user}"
DB_PASSWORD="${DB_PASSWORD:-auth_pass}"
DB_NAME="${DB_NAME:-auth_db}"

[ -f .env ] && set -a && source .env && set +a
export PGPASSWORD="${DB_PASSWORD}"

for f in migrations/000_initial.sql \
         migrations/001_add_session_id.sql \
         migrations/002_client_secret_hash.sql \
         migrations/003_add_allowed_scopes.sql \
         migrations/004_add_nonce_to_authorization_codes.sql \
         migrations/005_add_password_hash_to_users.sql; do
  echo "Running $f..."
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$f" -v ON_ERROR_STOP=1
done
echo "✅ マイグレーション完了"
