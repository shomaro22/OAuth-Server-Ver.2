-- 初期スキーマ（seed_step4 実行前に必要）
-- 実行: psql -h localhost -U postgres -d oauth_server -f migrations/000_initial.sql

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) NOT NULL,
  username VARCHAR(255),
  password_hash VARCHAR(255),
  email_verified BOOLEAN NOT NULL DEFAULT false,
  status VARCHAR(50),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_secret_hash VARCHAR(255),
  redirect_uris TEXT,
  allowed_scopes VARCHAR(512) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  session_token_hash VARCHAR(255) NOT NULL,
  ip_address VARCHAR(45),
  user_agent VARCHAR(512),
  token_version BIGINT NOT NULL DEFAULT 1,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(session_token_hash);

CREATE TABLE IF NOT EXISTS authorization_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  client_id UUID NOT NULL REFERENCES clients(id),
  session_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
  code_hash VARCHAR(255) NOT NULL UNIQUE,
  code_challenge VARCHAR(255),
  code_challenge_method VARCHAR(10),
  redirect_uri VARCHAR(512) NOT NULL,
  scopes VARCHAR(512),
  nonce VARCHAR(255),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON authorization_codes(client_id);

CREATE TABLE IF NOT EXISTS access_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  client_id UUID NOT NULL REFERENCES clients(id),
  session_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
  token_jti VARCHAR(255) NOT NULL UNIQUE,
  scopes VARCHAR(512),
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  access_token_id UUID NOT NULL,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false,
  rotated BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_access_token_id ON refresh_tokens(access_token_id);
