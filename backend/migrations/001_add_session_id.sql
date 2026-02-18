-- authorization_codes に session_id を追加（Token Version 照合用）
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS session_id UUID DEFAULT '00000000-0000-0000-0000-000000000000';
UPDATE authorization_codes SET session_id = '00000000-0000-0000-0000-000000000000' WHERE session_id IS NULL;

-- access_tokens に session_id を追加
ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS session_id UUID DEFAULT '00000000-0000-0000-0000-000000000000';
UPDATE access_tokens SET session_id = '00000000-0000-0000-0000-000000000000' WHERE session_id IS NULL;
