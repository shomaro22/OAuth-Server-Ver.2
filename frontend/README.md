# Frontend

ログイン・同意 UI。React Router で `/`, `/login`, `/consent`, `/callback` を接続。AuthContext で認証状態を管理し、RequireAuth で `/consent` を保護。

## 起動

```bash
cp .env.example .env
npm install
npm run dev
# http://localhost:5173
```

## テスト

```bash
npm run test:run    # Unit（Vitest）
npm run test:e2e   # E2E（Playwright、初回は npx playwright install chromium）
```
