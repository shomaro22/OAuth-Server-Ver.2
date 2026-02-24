# Backend

## 起動方法

```bash
# プロジェクトルートで
docker compose up -d postgres redis

# 環境変数
cp .env.example .env
# backend/.env の DB_PASSWORD=auth_passとなっているか確認

# マイグレーション・seed（初回のみ）
./scripts/migrate.sh
./scripts/seed_step4.sh password123 http://localhost:5173/callback

# 起動
go run ./cmd/server
```

本番では`OAUTH_ISSUER`をhttpsに設定する。

## テスト

```bash
# プロジェクトルートから（backend+frontend起動済み）
./scripts/run_all_tests.sh
```

証跡: `backend/tests/evidence/`
