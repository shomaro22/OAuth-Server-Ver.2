-- clients に allowed_scopes を追加（scope 検証用）
ALTER TABLE clients ADD COLUMN IF NOT EXISTS allowed_scopes VARCHAR(512) DEFAULT '';
