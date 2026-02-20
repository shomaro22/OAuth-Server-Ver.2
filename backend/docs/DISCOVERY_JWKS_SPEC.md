# Discovery / JWKS 仕様（契約）

## 1) JWKS (`/jwks`)

| 項目 | 仕様 |
|------|------|
| エンドポイント | `GET /jwks` |
| ステータス | `200 OK` |
| Content-Type | `application/json` |
| 形式 | RFC 7517 JWK Set `{"keys":[...]}` |
| keys | 配列（空不可。少なくとも 1 件） |
| 各 JWK 必須 | `kty`, `kid`, `use`, `alg`, `n`, `e` |
| kty | `"RSA"` |
| kid | 文字列（JWT ヘッダの kid と一致） |
| use | `"sig"` |
| alg | `"RS256"` |
| Cache-Control | `public, max-age=3600` |

## 2) Discovery (`/.well-known/openid-configuration`)

| 項目 | 仕様 |
|------|------|
| エンドポイント | `GET /.well-known/openid-configuration` |
| ステータス | `200 OK` |
| Content-Type | `application/json` |

### 必須フィールド

| フィールド | 値 |
|------------|-----|
| issuer | 絶対 URL（ID Token の iss と完全一致 MUST） |
| authorization_endpoint | `{issuer}/oauth/authorize` |
| token_endpoint | `{issuer}/oauth/token` |
| jwks_uri | `{issuer}/jwks` |
| userinfo_endpoint | `{issuer}/userinfo` |
| response_types_supported | `["code"]` |
| grant_types_supported | `["authorization_code","refresh_token"]` |
| subject_types_supported | `["public"]` |
| id_token_signing_alg_values_supported | `["RS256"]` |
| code_challenge_methods_supported | `["S256"]` |
| token_endpoint_auth_methods_supported | `["none","client_secret_basic"]` |
| scopes_supported | `["openid","profile","email"]` |
| claims_supported | `["sub","iss","aud","exp","iat","auth_time","nonce","sid"]` |

## 3) 一致条件（MUST）

- **Discovery の issuer** == **ID Token の iss**（完全一致）
- **JWT ヘッダの kid** は JWKS 内に同じ kid を持つ鍵が存在する
- **jwks_uri** の URL と実際の `/jwks` が一致する

## 4) 実装方針

- Auth Code + PKCE S256 only
- RS256 署名
- kid は JWT ヘッダに付与（デフォルト: `"default"`）
- Refresh Token は Cookie のみ（body には含めない）
- OAUTH_ISSUER を単一の設定値とし、全 endpoint URL を組み立てる
- **ローカル**: `http://localhost:8080`。**本番**: https 必須
