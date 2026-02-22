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

`backend/.env.example` を `backend/.env` にコピーし、値を設定（docker-compose と揃える）:

```bash
cp backend/.env.example backend/.env
# .env を編集して DB_PASSWORD 等を設定
```

`.env` の例（.env.example 参照）:
```
DB_HOST=localhost
DB_PORT=5432
DB_USER=auth_user
DB_PASSWORD=CHANGE_ME
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

## 5. 提出前テスト一括実行

```bash
# backend + frontend (npm run dev) 起動後、プロジェクトルートから
./scripts/run_all_tests.sh
```

証跡は `backend/tests/evidence/` に保存。提出 zip に含める。

### テスト・カバレッジ方針（Clean Architecture 準拠）

| 種別 | 対象 | 目標 |
|------|------|------|
| **Unit Coverage（Core）** | usecase / handler / jwt | **80%以上** |
| **Unit Coverage（Entity）** | entity | 参考指標 |
| **Integration / API Test** | DB / Redis 含む I/O 境界 | 担保 |
| **E2E** | authorize → login → consent → callback | ブラウザフロー担保 |
| **Load Test** | k6 閾値（p95/p99） | 満たす |

- **80% の対象**: ビジネスルール＋境界（usecase / handler / jwt）のみ。DB/GORM/Redis/Router/App/Scripts は Integration / E2E で担保。
- **E2E**: frontend を 5173 で起動。初回は `cd frontend && npx playwright install chromium`
- **k6**: 未インストール時は docker で実行

## 6. 提出用 zip について

- `node_modules/`、`frontend/dist/` は含めない（README の手順で再現）
