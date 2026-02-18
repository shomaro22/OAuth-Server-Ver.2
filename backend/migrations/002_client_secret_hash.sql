-- client_secret_hash（bcrypt）を追加
-- 新規クライアント登録時は bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost) でハッシュ化して保存すること
-- 既存 clients がある場合: 先にハッシュを埋めてから SET NOT NULL を実行すること
ALTER TABLE clients DROP COLUMN IF EXISTS client_secret;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS client_secret_hash VARCHAR(255);
-- 既存データ無し前提なら以下を実行:
-- ALTER TABLE clients ALTER COLUMN client_secret_hash SET NOT NULL;
