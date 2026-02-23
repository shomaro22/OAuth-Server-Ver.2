# Backend

## 起動

```bash
# 1. DB・Redis（プロジェクトルートで）
docker compose up -d postgres redis

# 2. 環境変数
cp .env.example .env
# DB_PASSWORD 等を docker-compose と揃える

# 3. マイグレーション・seed（初回のみ）
PGPASSWORD=auth_pass psql -h localhost -U auth_user -d auth_db -f migrations/000_initial.sql
# 001〜005 も実行
./scripts/seed_step4.sh password123 http://localhost:5173/callback

# 4. 起動
go run ./cmd/server
```

本番では `OAUTH_ISSUER` を https にすること。

## テスト

```bash
# プロジェクトルートから（backend + frontend 起動済み）
./scripts/run_all_tests.sh
```

証跡: `backend/tests/evidence/`
