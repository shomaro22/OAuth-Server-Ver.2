# OAuth 2.0 / OpenID Connect 認可サーバー

## 概要

OAuth 2.0 認可コードフロー + PKCE + OpenID Connect を実装した認可サーバー。  
Frontend（React）と Backend（Go）を分離し、PostgreSQL と Redis で状態を保持するステートレス構成。

## 技術スタック

| 種別 | 技術 |
|------|------|
| Frontend | React, TypeScript, Vite, React Router |
| Backend | Go, Echo |
| DB | PostgreSQL |
| Cache | Redis |
| JWT | RS256（RSA 秘密鍵） |

## アーキテクチャ

```
Frontend (5173) ──HTTP/API──► Backend (8080) ──► PostgreSQL
       │                              │
       └── credentials: include ──────┴──► Redis
```

| レイヤー | 責務 |
|----------|------|
| Frontend | ログイン・同意 UI（/login, /consent, /callback） |
| Backend | 認可 API、セッション、Discovery、JWKS、UserInfo |
| PostgreSQL | ユーザー、クライアント、セッション、トークン |
| Redis | 認可リクエスト（login_challenge）の一時保存 |

## セキュリティ設計

| 項目 | 方針 |
|------|------|
| JWT | RS256、JWKS で公開鍵配布 |
| PKCE | S256 必須 |
| セッション | Cookie（HttpOnly, SameSite=Lax） |
| CORS | 許可 Origin を env で制御 |
| ステートレス | 状態は Postgres/Redis に保持、水平スケール可能 |

## 実行方法（最短手順）

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

## 環境変数

`.env.example` をコピーして `.env` を作成する。

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

## テスト構成

```bash
# backend + frontend 起動後
./scripts/run_all_tests.sh
```

| 種別 | 証跡パス |
|------|----------|
| Unit | `backend/tests/evidence/unit/` |
| Integration | `backend/tests/evidence/integration/` |
| E2E | `backend/tests/evidence/e2e/` |
| Load (k6) | `backend/tests/evidence/load/` |
| Security | `backend/tests/evidence/security/` |

## OpenAPI

- **ファイル**: [docs/openapi.yaml](docs/openapi.yaml)
- Swagger Editor で開いて確認可能

## ディレクトリ構成

```
backend/    認可 API（Go, Echo）
frontend/   ログイン・同意 UI（React, Vite）
docs/       OpenAPI 仕様
scripts/    run_all_tests.sh, create_submission_zip.sh
k6/         負荷テスト
```

## 提出物

**提出 zip 名: `submission.zip`**

```bash
./scripts/run_all_tests.sh
./scripts/create_submission_zip.sh
# → submission.zip を提出
```

除外: `.env`, `node_modules/`, `frontend/dist/`, `frontend/test-results/`, `.DS_Store`, `__MACOSX`, `cookies.txt`

---

- [backend/README.md](backend/README.md) - 起動・マイグレーション・seed 詳細
- [frontend/README.md](frontend/README.md) - ルーティング・テスト詳細
