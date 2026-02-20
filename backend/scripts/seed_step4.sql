-- Step4 E2E 用 seed
-- 実行前に以下を置換してください：
--   {{USER_PASSWORD_HASH}}  → go run ./scripts/hash_user_password main の出力
--   {{CLIENT_ID}}           → uuidgen または SELECT gen_random_uuid() で生成した UUID
--   {{REDIRECT_URI}}        → 例: http://localhost:3000/callback
--   {{CLIENT_SECRET_HASH}}  → go run ./scripts/hash_client_secret.go your-secret の出力（任意、public client なら空でも可）

-- 1) users を1件登録
INSERT INTO users (id, email, username, password_hash, email_verified, status, created_at, updated_at)
VALUES (
  gen_random_uuid(),
  'test@example.com',
  'testuser',
  '{{USER_PASSWORD_HASH}}',
  false,
  'active',
  NOW(),
  NOW()
)
ON CONFLICT DO NOTHING;

-- 2) oauth_clients を1件登録（client_id = id）
-- redirect_uri は完全一致で登録。allowed_scopes に openid 必須。
INSERT INTO clients (id, client_secret_hash, redirect_uris, allowed_scopes)
VALUES (
  '{{CLIENT_ID}}'::uuid,
  COALESCE('{{CLIENT_SECRET_HASH}}', ''),
  '{{REDIRECT_URI}}',
  'openid profile'
)
ON CONFLICT (id) DO UPDATE SET
  redirect_uris = EXCLUDED.redirect_uris,
  allowed_scopes = EXCLUDED.allowed_scopes;
