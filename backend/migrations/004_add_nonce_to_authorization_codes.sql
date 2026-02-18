-- authorization_codes に nonce を追加（OIDC ID Token の nonce claim 用）
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS nonce VARCHAR(255) NOT NULL DEFAULT '';
