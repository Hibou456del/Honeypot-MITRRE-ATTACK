-- Fake database backup for honeypot
-- All data is fictional and for deception purposes only

CREATE DATABASE IF NOT EXISTS fake_production;
USE fake_production;

-- Fake users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert fake users
INSERT INTO users (username, password, email, role) VALUES
('admin', '$2y$10$fake_hash_admin_password_xyz', 'admin@fake-company.com', 'administrator'),
('user', '$2y$10$fake_hash_user_password_abc', 'user@fake-company.com', 'user'),
('backup', '$2y$10$fake_hash_backup_password_def', 'backup@fake-company.com', 'backup'),
('operator', '$2y$10$fake_hash_operator_password_ghi', 'operator@fake-company.com', 'operator');

-- Fake credentials table
CREATE TABLE credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service VARCHAR(50),
    username VARCHAR(50),
    password VARCHAR(255),
    api_key VARCHAR(100),
    description TEXT
);

INSERT INTO credentials (service, username, password, api_key, description) VALUES
('database', 'db_admin', 'fake_db_password_123', 'fake_db_key_abc456', 'Database access'),
('api', 'api_user', 'fake_api_password_789', 'fake_api_key_def012', 'API access'),
('backup', 'backup_user', 'fake_backup_password_345', 'fake_backup_key_ghi789', 'Backup service');

-- Fake configuration table
CREATE TABLE configuration (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(100),
    key_value TEXT,
    description TEXT
);

INSERT INTO configuration (key_name, key_value, description) VALUES
('secret_key', 'fake_secret_key_jkl012mno345', 'Application secret key'),
('encryption_key', 'fake_encryption_key_pqr678stu901', 'Data encryption key'),
('jwt_secret', 'fake_jwt_secret_vwx234yzw567', 'JWT token secret'),
('backup_encryption_key', 'fake_backup_key_bcd890efg123', 'Backup encryption key');

-- Fake sessions table
CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(100),
    user_id INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

INSERT INTO sessions (session_id, user_id, ip_address, user_agent, expires_at) VALUES
('fake_session_abc123', 1, '192.168.1.100', 'Mozilla/5.0 Fake Browser', DATE_ADD(NOW(), INTERVAL 1 HOUR)),
('fake_session_def456', 2, '192.168.1.101', 'Mozilla/5.0 Fake Browser', DATE_ADD(NOW(), INTERVAL 1 HOUR));