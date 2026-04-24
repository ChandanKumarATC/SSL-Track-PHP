<?php
/**
 * SSL & Domain Expiry Tracker - Configuration
 * 
 * Main configuration file for the application.
 * Contains database settings, email configuration, and other constants.
 */

// Database Configuration
define('DB_HOST', $_ENV['DB_HOST'] ?? 'localhost');
define('DB_NAME', $_ENV['DB_NAME'] ?? 'ssl_domain_tracker');
define('DB_USER', $_ENV['DB_USER'] ?? 'root');
define('DB_PASS', $_ENV['DB_PASS'] ?? '');
define('DB_CHARSET', 'utf8mb4');

// Email Configuration
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', $_ENV['SMTP_USERNAME'] ?? 'atc.domain.track@gmail.com');
define('SMTP_PASSWORD', $_ENV['SMTP_PASSWORD'] ?? '');
define('SMTP_FROM_EMAIL', 'atc.domain.track@gmail.com');
define('SMTP_FROM_NAME', 'SSL & Domain Tracker');

// Application Settings
define('APP_NAME', 'SSL & Domain Expiry Tracker');
define('APP_VERSION', '1.0.0');
define('SESSION_TIMEOUT', 3600); // 1 hour in seconds

// Notification Thresholds
define('SSL_EXPIRY_WARNING_DAYS', 7);
define('DOMAIN_EXPIRY_WARNING_DAYS', 30);

// File Paths
define('LOG_DIR', __DIR__ . '/../logs');
define('SSL_CERT_DIR', __DIR__ . '/../ssl');
define('CRON_DIR', __DIR__ . '/../cron');

// Security Settings
define('CSRF_TOKEN_NAME', 'csrf_token');
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900); // 15 minutes

// Monitoring Settings
define('WHOIS_TIMEOUT', 30);
define('SSL_TIMEOUT', 30);
define('MAX_RETRY_ATTEMPTS', 3);
define('RETRY_DELAY_SECONDS', 5);

// Create required directories if they don't exist
$directories = [LOG_DIR, SSL_CERT_DIR, CRON_DIR];
foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}
?>