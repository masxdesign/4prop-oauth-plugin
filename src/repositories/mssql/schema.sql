-- Auth Plugin - MSSQL Schema

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
    last_login DATETIME DEFAULT GETDATE()
);

-- Indexes for performance
CREATE INDEX idx_email ON a_rcUsers(email);
CREATE INDEX idx_oauth ON a_rcUsers(oauth_provider, oauth_id);
