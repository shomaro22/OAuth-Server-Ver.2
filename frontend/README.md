# OAuth 認可サーバー Frontend

React + TypeScript + Vite によるログイン・同意 UI。

## 構成

- **API 層**: `src/lib/api.ts`（`apiFetch` で通信層分離・エラーハンドリング）
- **状態管理**: `src/features/auth/AuthContext.tsx`（認証状態）
- **ルートガード**: `src/features/auth/RequireAuth.tsx`（`/consent` はログイン済み必須）
- **型定義**: `src/types/oidc.ts`（API レスポンス型、any 禁止）

## セットアップ

```bash
cp .env.example .env
# VITE_API_BASE を必要に応じて編集
npm install
```

## 起動

```bash
npm run dev
# http://localhost:5173
```

## Lint / Format

```bash
npm run lint
npm run format
npm run format:check
```

## E2E

```bash
npm run test:e2e
# 初回: npx playwright install chromium
```
