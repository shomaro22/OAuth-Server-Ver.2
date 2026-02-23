# 提出前チェックリスト

## 1) Discovery / JWKS / Token の整合

```bash
cd backend
./scripts/verify_oidc.sh
# ID Token の iss/kid 自動検証（token 取得後）
./scripts/verify_id_token.sh http://localhost:8080 "$ID_TOKEN"
```

確認項目:
- [ ] issuer と id_token の iss が完全一致（verify_id_token.sh で自動確認可）
- [ ] jwks_uri が到達可能で /jwks が keys[] を返す
- [ ] JWT ヘッダの kid が JWKS 内の kid と一致
- [ ] alg が RS256 で統一

## 2) Discovery の「嘘」なし

- [ ] token_endpoint_auth_methods_supported が実装と一致（Basic 対応済みなら `["none","client_secret_basic"]`）
- [ ] scopes_supported と UserInfo の返却が整合（email 返すなら scopes に email）
- [ ] userinfo_endpoint は実装済みなら出す

## 3) 失敗系の挙動

```bash
cd backend
./scripts/verify_failure_cases.sh
```

確認項目:
- [ ] /oauth/authorize: redirect_uri 不一致 → エラー
- [ ] /oauth/token: code 二回使用 → invalid_grant
- [ ] /oauth/token: code 期限切れ → invalid_grant
- [ ] /oauth/token: redirect_uri 不一致 → invalid_grant
- [ ] /oauth/token: PKCE verifier 不一致 → invalid_grant
- [ ] refresh: cookie なし → invalid_request
- [ ] refresh: rotation 後の古い RT → invalid_grant

## 4) 提出 zip

```bash
# プロジェクトルートから（node_modules / .env / .DS_Store / cookies.txt を自動除外）
./scripts/create_submission_zip.sh
# → submission.zip が作成される
```

チェック項目:
- [ ] node_modules/ を含めない
- [ ] .env を含めない（.env.example を置き、README で手順を記載）
- [ ] frontend/dist/ を含めない（README で再現手順を記載）
- [ ] frontend/test-results/, frontend/playwright-report/ を含めない
- [ ] .DS_Store / cookies.txt / __MACOSX を含めない
