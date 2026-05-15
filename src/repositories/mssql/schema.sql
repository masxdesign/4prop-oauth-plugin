-- Auth Plugin - MSSQL Schema (reference / starter)
--
-- Production schemas may have additional columns (hash, neg_id, role, etc.)
-- that the 4prop monorepo carries. This file documents the minimum required
-- for the auth + email-verification flows.

CREATE TABLE a_rcUsers (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    email VARCHAR(75) UNIQUE NOT NULL,
    password TEXT NULL,
    first VARCHAR(30) NULL,
    last VARCHAR(30) NULL,
    oauth_provider VARCHAR(20) NULL,
    oauth_id VARCHAR(100) NULL,
    avatar TEXT NULL,
    created_at DATETIME DEFAULT GETDATE(),
    last_login DATETIME DEFAULT GETDATE(),
    -- Email verification
    email_verified_at DATETIME NULL,
    email_verify_token_hash VARCHAR(64) NULL,
    email_verify_token_expires_at DATETIME NULL
);

CREATE INDEX idx_email ON a_rcUsers(email);
CREATE INDEX idx_oauth ON a_rcUsers(oauth_provider, oauth_id);

-- Filtered index on token hash so the verify lookup stays small.
CREATE INDEX IX_a_rcUsers_email_verify_token_hash
    ON a_rcUsers(email_verify_token_hash)
    WHERE email_verify_token_hash IS NOT NULL;

-- Resend rate-limiting: 60s cooldown + 5/24h cap. Append-only.
CREATE TABLE a_rcEmailVerifyAttempts (
    id INT IDENTITY(1,1) PRIMARY KEY,
    email VARCHAR(75) NOT NULL,
    sent_at DATETIME NOT NULL DEFAULT (SYSUTCDATETIME())
);
CREATE INDEX IX_a_rcEmailVerifyAttempts_email_sent_at
    ON a_rcEmailVerifyAttempts(email, sent_at DESC);
