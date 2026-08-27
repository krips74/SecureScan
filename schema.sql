CREATE DATABASE IF NOT EXISTS securescan CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securescan;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL,
    email         VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('admin','user') DEFAULT 'user',
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME,
    is_active     BOOLEAN DEFAULT TRUE
);

-- Non-unique index for faster lookups (username is not unique by design)
CREATE INDEX idx_users_username ON users(username);

-- Scan history table
CREATE TABLE IF NOT EXISTS scans (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    target_url    VARCHAR(500) NOT NULL,
    scan_types    LONGTEXT,
    status        ENUM('running','completed','failed') DEFAULT 'running',
    cancel_requested BOOLEAN DEFAULT FALSE,
    cancel_reason  VARCHAR(255),
    canceled_at    DATETIME,
    total_vulns   INT DEFAULT 0,
    severity      ENUM('critical','high','medium','low','info','clean') DEFAULT 'info',
    results_json  LONGTEXT,
    started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at  DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Vulnerabilities table (denormalized for fast dashboard queries)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    scan_id      INT NOT NULL,
    vuln_type    VARCHAR(50),
    severity     ENUM('critical','high','medium','low','info') DEFAULT 'medium',
    triage_status ENUM('unreviewed','confirmed','false_positive') DEFAULT 'unreviewed',
    triaged_at    DATETIME,
    url          VARCHAR(500),
    parameter    VARCHAR(100),
    payload      TEXT,
    description  TEXT,
    found_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Indexes for fast lookups
CREATE INDEX idx_scans_user ON scans(user_id);
CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);

-- Password reset (email OTP) table
CREATE TABLE IF NOT EXISTS password_resets (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    user_id           INT NOT NULL,
    otp_hash          CHAR(64) NOT NULL,
    otp_expires_at    DATETIME NOT NULL,
    otp_verified_at   DATETIME NULL,
    reset_token_hash  CHAR(64) NULL,
    reset_expires_at  DATETIME NULL,
    attempts          INT DEFAULT 0,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_password_resets_user ON password_resets(user_id);
CREATE INDEX idx_password_resets_otp_exp ON password_resets(otp_expires_at);
CREATE INDEX idx_password_resets_reset_exp ON password_resets(reset_expires_at);

-- Email verification tokens
CREATE TABLE IF NOT EXISTS email_verifications (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    token_hash  CHAR(64) NOT NULL,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_ev_token (token_hash)
);

CREATE INDEX idx_ev_user ON email_verifications(user_id);
CREATE INDEX idx_ev_exp ON email_verifications(expires_at);

-- Feedback table
CREATE TABLE IF NOT EXISTS feedback (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    subject       VARCHAR(200) NOT NULL,
    message       TEXT NOT NULL,
    category      ENUM('bug','feature','false_positive','general') DEFAULT 'general',
    status        ENUM('pending','resolved') DEFAULT 'pending',
    admin_reply   TEXT,
    replied_at    DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_feedback_user ON feedback(user_id);
CREATE INDEX idx_feedback_status ON feedback(status);
CREATE INDEX idx_feedback_category ON feedback(category);
CREATE INDEX idx_feedback_created ON feedback(created_at);

-- Admin sessions table (tracks admin cookie sessions)
CREATE TABLE IF NOT EXISTS admin_sessions (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    session_id     CHAR(36) NOT NULL,
    admin_email    VARCHAR(120) NOT NULL,
    ip_address     VARCHAR(45),
    user_agent     VARCHAR(255),
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    logged_out_at  DATETIME,
    UNIQUE KEY uq_admin_session_id (session_id)
);

CREATE INDEX idx_admin_sessions_email ON admin_sessions(admin_email);
CREATE INDEX idx_admin_sessions_last_seen ON admin_sessions(last_seen_at);
