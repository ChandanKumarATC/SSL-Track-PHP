-- SSL & Domain Expiry Tracker Database Schema
-- MySQL/MariaDB database schema for the SSL & Domain Expiry Tracking Application

-- Create database (run manually if needed)
-- CREATE DATABASE ssl_domain_tracker CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE ssl_domain_tracker;

-- Tracking items table - stores domains and SSL certificates being monitored
CREATE TABLE tracking_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL COMMENT 'Display name for the tracking item',
    type ENUM('domain', 'ssl') NOT NULL COMMENT 'Type of item being tracked',
    hostname VARCHAR(255) NOT NULL COMMENT 'Domain name or hostname',
    port INT DEFAULT 443 COMMENT 'Port number for SSL certificates',
    registrar VARCHAR(255) COMMENT 'Domain registrar (optional)',
    admin_emails TEXT COMMENT 'JSON array of admin email addresses',
    expiry_date DATETIME COMMENT 'Expiration date of domain or certificate',
    last_checked DATETIME COMMENT 'Last time this item was checked',
    status ENUM('active', 'warning', 'expired', 'error') DEFAULT 'active' COMMENT 'Current status of the item',
    error_message TEXT COMMENT 'Last error message if any',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_expiry_date (expiry_date),
    INDEX idx_type_status (type, status),
    INDEX idx_hostname (hostname),
    INDEX idx_last_checked (last_checked)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- SSL certificates table - additional data for SSL certificate tracking items
CREATE TABLE ssl_certificates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    tracking_item_id INT NOT NULL COMMENT 'Reference to tracking_items table',
    issuer VARCHAR(255) COMMENT 'Certificate issuer (CA)',
    subject VARCHAR(255) COMMENT 'Certificate subject',
    is_wildcard BOOLEAN DEFAULT FALSE COMMENT 'Whether this is a wildcard certificate',
    certificate_path VARCHAR(500) COMMENT 'Path to certificate file',
    private_key_path VARCHAR(500) COMMENT 'Path to private key file',
    chain_path VARCHAR(500) COMMENT 'Path to certificate chain file',
    auto_renew BOOLEAN DEFAULT TRUE COMMENT 'Whether to auto-renew this certificate',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (tracking_item_id) REFERENCES tracking_items(id) ON DELETE CASCADE,
    INDEX idx_tracking_item (tracking_item_id)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Notification history table - tracks sent notifications to prevent duplicates
CREATE TABLE notification_history (
    id INT PRIMARY KEY AUTO_INCREMENT,
    tracking_item_id INT NOT NULL COMMENT 'Reference to tracking_items table',
    notification_type ENUM('ssl_expiry', 'domain_expiry') NOT NULL COMMENT 'Type of notification',
    days_remaining INT NOT NULL COMMENT 'Days remaining until expiry when notification was sent',
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the notification was sent',
    email_status ENUM('sent', 'failed', 'retry') DEFAULT 'sent' COMMENT 'Status of email delivery',
    error_message TEXT COMMENT 'Error message if email failed',
    recipient_emails TEXT COMMENT 'JSON array of recipient email addresses',
    
    FOREIGN KEY (tracking_item_id) REFERENCES tracking_items(id) ON DELETE CASCADE,
    INDEX idx_sent_at (sent_at),
    INDEX idx_tracking_item_type (tracking_item_id, notification_type)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Configuration table - stores application configuration settings
CREATE TABLE app_config (
    config_key VARCHAR(100) PRIMARY KEY COMMENT 'Configuration key',
    config_value TEXT NOT NULL COMMENT 'Configuration value (JSON or plain text)',
    description TEXT COMMENT 'Description of this configuration setting',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- User sessions table - manages web application sessions
CREATE TABLE user_sessions (
    session_id VARCHAR(128) PRIMARY KEY COMMENT 'PHP session ID',
    user_data TEXT COMMENT 'Serialized user session data',
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Last activity timestamp',
    expires_at TIMESTAMP NOT NULL COMMENT 'Session expiration timestamp',
    ip_address VARCHAR(45) COMMENT 'Client IP address',
    user_agent TEXT COMMENT 'Client user agent string',
    
    INDEX idx_expires_at (expires_at),
    INDEX idx_last_activity (last_activity)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- System logs table - stores application logs and events
CREATE TABLE system_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    log_level ENUM('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL') NOT NULL COMMENT 'Log severity level',
    component VARCHAR(100) NOT NULL COMMENT 'Application component that generated the log',
    message TEXT NOT NULL COMMENT 'Log message',
    context_data JSON COMMENT 'Additional context data as JSON',
    tracking_item_id INT COMMENT 'Related tracking item if applicable',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (tracking_item_id) REFERENCES tracking_items(id) ON DELETE SET NULL,
    INDEX idx_created_at (created_at),
    INDEX idx_log_level (log_level),
    INDEX idx_component (component),
    INDEX idx_tracking_item (tracking_item_id)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Insert default configuration values
INSERT INTO app_config (config_key, config_value, description) VALUES
('smtp_enabled', 'true', 'Whether email notifications are enabled'),
('monitoring_enabled', 'true', 'Whether automated monitoring is enabled'),
('ssl_check_interval', '86400', 'SSL certificate check interval in seconds (24 hours)'),
('domain_check_interval', '86400', 'Domain expiry check interval in seconds (24 hours)'),
('max_concurrent_checks', '10', 'Maximum number of concurrent monitoring checks'),
('log_retention_days', '30', 'Number of days to retain log entries'),
('session_cleanup_interval', '3600', 'Session cleanup interval in seconds (1 hour)'),
('notification_cooldown', '86400', 'Cooldown period between duplicate notifications in seconds (24 hours)');

-- Create a view for dashboard summary statistics
CREATE VIEW dashboard_summary AS
SELECT 
    COUNT(*) as total_items,
    SUM(CASE WHEN type = 'domain' THEN 1 ELSE 0 END) as total_domains,
    SUM(CASE WHEN type = 'ssl' THEN 1 ELSE 0 END) as total_ssl_certs,
    SUM(CASE WHEN type = 'domain' AND expiry_date <= DATE_ADD(NOW(), INTERVAL 30 DAY) AND expiry_date > NOW() THEN 1 ELSE 0 END) as domains_expiring_soon,
    SUM(CASE WHEN type = 'ssl' AND expiry_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) AND expiry_date > NOW() THEN 1 ELSE 0 END) as ssl_expiring_soon,
    SUM(CASE WHEN expiry_date <= NOW() THEN 1 ELSE 0 END) as expired_items,
    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_items
FROM tracking_items
WHERE status != 'deleted';