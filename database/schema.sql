-- SecureCode AI - MySQL schema (optional: the backend also creates these tables automatically).
-- 1) mysql -u root -p < database/schema.sql
-- 2) set in backend/.env:  DATABASE_URL=mysql+pymysql://securecode:securecode_pw@localhost:3306/securecode_ai
CREATE DATABASE IF NOT EXISTS securecode_ai CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'securecode'@'localhost' IDENTIFIED BY 'securecode_pw';
GRANT ALL PRIVILEGES ON securecode_ai.* TO 'securecode'@'localhost';
FLUSH PRIVILEGES;
USE securecode_ai;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  settings JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  filename VARCHAR(255) NOT NULL DEFAULT 'untitled',
  language VARCHAR(30) NOT NULL DEFAULT 'unknown',
  code LONGTEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'success',
  error TEXT NULL,
  kind VARCHAR(20) NOT NULL DEFAULT 'scan',
  parent_scan_id INT NULL,
  iteration INT NOT NULL DEFAULT 1,
  score INT NOT NULL DEFAULT 0,
  grade VARCHAR(2) NOT NULL DEFAULT '-',
  rating VARCHAR(60) NOT NULL DEFAULT '',
  explanation TEXT NOT NULL,
  counts JSON NULL,
  breakdown JSON NULL,
  total_findings INT NOT NULL DEFAULT 0,
  lines_scanned INT NOT NULL DEFAULT 0,
  execution JSON NULL,
  duration_ms INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX ix_scans_user (user_id), INDEX ix_scans_parent (parent_scan_id), INDEX ix_scans_created (created_at),
  CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS findings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  scan_id INT NOT NULL,
  rule_id VARCHAR(60) NOT NULL,
  title VARCHAR(160) NOT NULL,
  severity VARCHAR(10) NOT NULL,
  cwe VARCHAR(20) NOT NULL DEFAULT '',
  owasp VARCHAR(100) NOT NULL DEFAULT '',
  line INT NOT NULL,
  snippet TEXT NOT NULL,
  message TEXT NOT NULL,
  cause TEXT NOT NULL,
  impact TEXT NOT NULL,
  how_to_fix TEXT NOT NULL,
  fixable TINYINT(1) NOT NULL DEFAULT 0,
  fix JSON NULL,
  INDEX ix_findings_scan (scan_id),
  CONSTRAINT fk_findings_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  action VARCHAR(60) NOT NULL,
  detail VARCHAR(255) NOT NULL DEFAULT '',
  ip VARCHAR(64) NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX ix_audit_user (user_id)
) ENGINE=InnoDB;
