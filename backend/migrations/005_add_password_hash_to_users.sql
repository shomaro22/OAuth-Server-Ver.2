-- users テーブルに password_hash を追加（ログイン認証用）
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
