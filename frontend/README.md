# Frontend - Authorization UI + Dev OAuth Client

React+TypeScript+Viteで構築された認可サーバーUI。

---

## ページ構成

- /
- /login
- /consent
- /callback
- /dev/oauth-client（開発専用）

---

## Dev OAuth Client

開発用テストクライアント。

### 機能

- PKCE (S256) 生成（WebCrypto）
- code_verifierをsessionStorageに保存
- code → token交換
- /userinfo呼び出し
- 状態クリア

---

## 注意事項

Refresh TokenはSecure属性付きのHttpOnly Cookieです。

Secure属性により、HTTP（http://localhost）では送信されません。
そのため、ブラウザでのrefresh動作確認はできません。

refresh検証はcurlで実施してください。

---

## 起動方法

```bash
cp .env.example .env
npm install
npm run dev
```
