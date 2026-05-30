# OAuth 2.0 / OpenID Connect 認可サーバー

OAuth 2.0認可コードフロー+PKCE (S256)+OpenID Connectを実装した認可サーバー。  
Frontend（React）とBackend（Go）を分離し、JWTベースで、状態はDB/Redisに保持。

**本番（フロント）**: https://oauth-server-ver-2.vercel.app

---

## 前提条件

| 要件                  | 目安 　                                   |
| --------------------- | ----------------------------------------- |
| Go                    | 1.22+                                     |
| Node.js               | 18+                                       |
| Docker/Docker Compose | v2+                                       |
| psql                  | PostgreSQLクライアント（migrate/seed 用） |

---

## Quick Start

```bash
# 1. DB・Redisのみ起動（Backendはローカルでgo run）
docker compose up -d postgres redis

# 2. 環境変数
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
# backend/.envのDB_PASSWORD=auth_passとなっているか確認

# 3. マイグレーション・seed
cd backend
./scripts/migrate.sh
./scripts/seed_step4.sh password123 http://localhost:5173/callback
cd ..

# 4. Backend起動（別ターミナル）
cd backend && go run ./cmd/server

# 5. Frontend起動（別ターミナル）
cd frontend && npm install && npm run dev
```

- Backend: http://localhost:8080
- Frontend: http://localhost:5173

> **補足**: `docker compose up -d` で auth-server も起動可能。ローカル開発では postgres + redis のみ起動し、Backend を `go run` で動かす想定。

---

## 技術スタック

| 種別     | 技術                               |
| -------- | ---------------------------------- |
| Frontend | React,TypeScript,Vite,React Router |
| Backend  | Go,Echo                            |
| DB       | PostgreSQL                         |
| Cache    | Redis                              |
| JWT      | RS256（RSA 2048bit）               |

---

## アーキテクチャ

```
Frontend (5173) ──HTTP/API──► Backend(8080) ──► PostgreSQL
       │                              │
       └── credentials:  include ─────┴──► Redis
```

---

## セキュリティ設計

| 項目          | 方針                                        |
| ------------- | ------------------------------------------- |
| JWT           | RS256、JWKSで公開鍵配布                     |
| PKCE          | S256必須                                    |
| Refresh Token | Cookie-only（HttpOnly,Secure,SameSite=Lax） |
| CORS          | 許可Originをenvで制御                       |
| access_token  | 有効期限 300秒                              |

---

## 動作確認（開発用テストクライアント）

1. http://localhost:5173/dev/oauth-client アクセス
2. 「Login with OAuth」→ ログイン（testuser/password123）→ 同意
3. Callback → 「Devクライアントで続行」→ 「Exchange code → token」→ 「Call/userinfo」
4. access_token/id_token/userinfoが表示されれば成功

---

## Refresh Token 検証について

Refresh TokenはSecure Cookieのため、HTTPでは送信されません。
そのため refresh検証は curlで実施してください。

```bash
# code 取得
./scripts/dev_authorize.sh

# token交換（code/code_verifierをgen_pkce.js出力から取得）
curl -i -c cookies.txt -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=11111111-1111-1111-1111-111111111111" \
  -d "redirect_uri=http://localhost:5173/callback" \
  -d "code=CODE" \
  -d "code_verifier=VERIFIER"

# refresh（Set-Cookieが更新されればRotation成功）
curl -i -b cookies.txt -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=11111111-1111-1111-1111-111111111111"
```

> 代替: mkcert で https://localhost を用意すればブラウザでもrefresh検証可能。

---

## テスト一括実行

```bash
# backend+frontend起動後
./scripts/run_all_tests.sh
```

証跡: `backend/tests/evidence/`

---

## CI/CD（GitHub Actions）

[`.github/workflows/ci.yml`](.github/workflows/ci.yml)

- `backend`: `go vet`・単体テスト
- `frontend`: ESLint・本番ビルド

[`.github/workflows/deploy-frontend-vercel.yml`](.github/workflows/deploy-frontend-vercel.yml)

- `pull_request`: Vercel Preview デプロイ
- `main` / `master` push・`workflow_dispatch`: Vercel Production デプロイ

### GitHub Secrets（OAuth-Server-Ver.2 リポジトリ）

| Secret              | 説明                                                        |
| ------------------- | ----------------------------------------------------------- |
| `VERCEL_TOKEN`      | Vercel Personal Token                                       |
| `VERCEL_ORG_ID`     | `frontend` で `npx vercel link` 後の `orgId`                |
| `VERCEL_PROJECT_ID` | 同上 `projectId`（**OAuth 用に別プロジェクト推奨**）        |
| `VITE_API_BASE`     | バックエンド API の URL（Render 等。README には記載しない） |

> attendance-app は `VITE_API_BASE_URL` ですが、本リポジトリは **`VITE_API_BASE`** です。

### Vercel（frontend）

- Root Directory: `frontend`
- 環境変数 `VITE_API_BASE` = バックエンド API の URL
- `frontend/vercel.json` で SPA ルーティング設定済み

### Backend 環境変数（API の URL・Vercel フロントに合わせる）

- `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` / `DB_SSLMODE=require`（Neon）
- `REDIS_ADDR`（例: `red-xxxxx:6379`）。任意で `REDIS_PASSWORD` / `REDIS_DB`
- `SERVER_BASE_URL` / `OAUTH_ISSUER` = バックエンド API の URL
- `CORS_ORIGIN` = `https://oauth-server-ver-2.vercel.app`
- `LOGIN_URL` = `https://oauth-server-ver-2.vercel.app/login`
- `CONSENT_URL` = `https://oauth-server-ver-2.vercel.app/consent`
- `AUTO_MIGRATE_ON_START` = `true`（起動時に SQL マイグレーション。Render 無料枠向け）
- `AUTO_SEED_ON_START` = `true`（`testuser` / 固定 OAuth クライアントを upsert。migrate の後に有効化）
- `AUTO_SEED_PASSWORD` = `password123`（任意）
- `AUTO_SEED_REDIRECT_URI`（任意。未設定時は `CORS_ORIGIN` + `/callback`）

Render で Go を動かす場合:

| 項目           | 値                                    |
| -------------- | ------------------------------------- |
| Root Directory | `backend`                             |
| Build Command  | `go build -o bin/server ./cmd/server` |
| Start Command  | `./bin/server`                        |

### 初回 DB セットアップ（Neon 接続後）

**Render 本番（推奨）**: Environment に以下を追加して再デプロイするだけです。

- `AUTO_MIGRATE_ON_START=true`
- `AUTO_SEED_ON_START=true`
- `AUTO_SEED_REDIRECT_URI=https://oauth-server-ver-2.vercel.app/callback`

ログに `Applied migration:` / `Auto seed complete` が出れば完了です。

**ローカルから手動**する場合:

```bash
cd backend
cp .env.example .env
# .env に Neon の DB_* を記入

./scripts/migrate.sh
./scripts/seed_step4.sh password123 https://oauth-server-ver-2.vercel.app/callback
```

テストユーザー: `testuser` / `password123`（`AUTO_SEED_PASSWORD` と同じ）

### GitHub Secret `VITE_API_BASE`

フロントの API 向き先（**末尾に `/api` は付けない**。本リポジトリはパス直指定）。値は Render 等のダッシュボードで確認し、Secrets に登録する。

---

## 詳細

- [backend/README.md](backend/README.md)
- [frontend/README.md](frontend/README.md)
- [docs/openapi.yaml](docs/openapi.yaml)
