# OAuth 2.0 / OIDC 認可サーバー

OAuth 2.0 認可コードフロー + PKCE + OpenID Connect を実装した認可サーバー。  
Backend（Go + Echo）と Frontend（React + Vite）の分離構成。

## 構成

| ディレクトリ | 役割 |
|-------------|------|
| `backend/` | 認可サーバー API（Go, Echo, PostgreSQL, Redis） |
| `frontend/` | ログイン・同意 UI（React, Vite） |
| `docker-compose.yml` | 開発・本番共通の基盤（Postgres, Redis, auth-server） |
| `compose.prod.yml` | 本番用オーバーライド |

## ステートレスバックエンド

**アプリケーションサーバーは水平スケール可能です。**  
セッション・トークン・認可リクエストなどの状態はすべて **PostgreSQL / Redis** に保持しており、プロセス内に状態を持ちません。

## 環境変数

提出物には `.env` 実体を含めません。`.env.example` をコピーして `.env` を作成してください。

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
# 必要に応じて編集
```

## 起動手順（1本化）

### 開発（DEV）

```bash
# 1. DB・Redis 起動
docker compose up -d postgres redis

# 2. マイグレーション・seed（初回のみ）
cd backend
PGPASSWORD=auth_pass psql -h localhost -U auth_user -d auth_db -f migrations/000_initial.sql
# 001〜005 も実行
./scripts/seed_step4.sh password123 http://localhost:5173/callback
cd ..

# 3. Backend 起動（別ターミナル）
cd backend && go run ./cmd/server

# 4. Frontend 起動（別ターミナル）
cd frontend && npm install && npm run dev
```

- Backend: http://localhost:8080  
- Frontend: http://localhost:5173  

### 本番（PROD）Docker Compose

```bash
# 本番用 compose を重ねて起動（OAUTH_ISSUER 等を本番値に）
docker compose -f docker-compose.yml -f compose.prod.yml up -d
```

`compose.prod.yml` で本番用の環境変数（`OAUTH_ISSUER` を https に等）を上書きします。  
開発時は `docker compose up -d` のみで OK。

### 全サービス Docker 起動（開発用）

```bash
# Backend も Docker で起動する場合
docker compose up -d
# Backend: 8080, Postgres: 5432, Redis: 6379
# Frontend は別途 npm run dev
```

## テスト・証跡

```bash
# backend + frontend 起動後、プロジェクトルートから
./scripts/run_all_tests.sh
```

証跡は `backend/tests/evidence/` に保存。提出 zip に含めます。

## 提出用 zip

```bash
./scripts/create_submission_zip.sh
# → submission.zip（node_modules / .env / .DS_Store 除外）
```

## 詳細

- **Backend**: [backend/README.md](backend/README.md)
- **Frontend**: [frontend/README.md](frontend/README.md)
- **提出チェックリスト**: [backend/docs/SUBMISSION_CHECKLIST.md](backend/docs/SUBMISSION_CHECKLIST.md)
