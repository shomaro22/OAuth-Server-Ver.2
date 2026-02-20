# OAuth Server Backend

## 前提

- **本番環境では OAUTH_ISSUER を https にすること**（Discovery / ID Token の iss 整合のため）
- ローカル開発は `http://localhost:8080` で統一

## 1. データベース（PostgreSQL）・Redis

```bash
# プロジェクトルートで実行
docker compose up -d postgres redis
```

## 2. 環境変数

`backend/.env` に以下を設定（docker-compose と揃える）:

```
DB_HOST=localhost
DB_PORT=5432
DB_USER=auth_user
DB_PASSWORD=auth_pass
DB_NAME=auth_db
OAUTH_ISSUER=http://localhost:8080
```

## 3. マイグレーション・seed

```bash
cd backend
PGPASSWORD=auth_pass psql -h localhost -U auth_user -d auth_db -f migrations/000_initial.sql
# 001〜005 も実行
./scripts/seed_step4.sh password123 http://localhost:5173/callback
```

## 4. 起動

```bash
cd backend
go run ./cmd/server
```

`Successfully connected to PostgreSQL` と表示されれば接続成功。

## 5. 提出用 zip について

- `node_modules/`、`frontend/dist/` は含めない（README の手順で再現）
