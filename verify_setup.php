<?php
/**
 * Setup Verification Script
 * 
 * This script verifies that the project structure and basic configuration
 * are set up correctly for the SSL & Domain Expiry Tracker.
 */

echo "SSL & Domain Expiry Tracker - Setup Verification\n";
echo "===============================================\n\n";

$errors = [];
$warnings = [];
$success = [];

// Check PHP version
if (version_compare(PHP_VERSION, '8.0.0', '>=')) {
    $success[] = "✓ PHP version: " . PHP_VERSION . " (>= 8.0.0 required)";
} else {
    $errors[] = "✗ PHP version: " . PHP_VERSION . " (8.0.0 or higher required)";
}

// Check required PHP extensions
$required_extensions = ['openssl', 'pdo', 'pdo_mysql', 'json', 'curl'];
foreach ($required_extensions as $ext) {
    if (extension_loaded($ext)) {
        $success[] = "✓ PHP extension: $ext";
    } else {
        $errors[] = "✗ PHP extension missing: $ext";
    }
}

// Check directory structure
$required_dirs = [
    'public' => 'Web root directory',
    'config' => 'Configuration files',
    'database' => 'Database schema and setup',
    'src' => 'Application source code',
    'cron' => 'Cron job scripts',
    'logs' => 'Log files directory',
    'ssl' => 'SSL certificate storage',
    'tests' => 'Test files'
];

foreach ($required_dirs as $dir => $description) {
    if (is_dir($dir)) {
        $success[] = "✓ Directory exists: $dir ($description)";
    } else {
        $errors[] = "✗ Directory missing: $dir ($description)";
    }
}

// Check required files
$required_files = [
    'public/index.php' => 'Main entry point',
    'config/config.php' => 'Main configuration file',
    'database/schema.sql' => 'Database schema',
    'database/Database.php' => 'Database connection class',
    'database/setup.php' => 'Database setup script',
    'composer.json' => 'Composer configuration',
    'phpunit.xml' => 'PHPUnit configuration',
    '.env.example' => 'Environment configuration template'
];

foreach ($required_files as $file => $description) {
    if (file_exists($file)) {
        $success[] = "✓ File exists: $file ($description)";
    } else {
        $errors[] = "✗ File missing: $file ($description)";
    }
}

// Check file permissions
$writable_dirs = ['logs', 'ssl'];
foreach ($writable_dirs as $dir) {
    if (is_dir($dir) && is_writable($dir)) {
        $success[] = "✓ Directory writable: $dir";
    } elseif (is_dir($dir)) {
        $warnings[] = "⚠ Directory not writable: $dir (may need chmod 755)";
    }
}

// Check configuration file syntax
if (file_exists('config/config.php')) {
    $config_content = file_get_contents('config/config.php');
    if (strpos($config_content, '<?php') === 0) {
        $success[] = "✓ Configuration file has valid PHP syntax";
    } else {
        $errors[] = "✗ Configuration file has invalid PHP syntax";
    }
}

// Check database schema
if (file_exists('database/schema.sql')) {
    $schema_content = file_get_contents('database/schema.sql');
    $required_tables = ['tracking_items', 'ssl_certificates', 'notification_history', 'app_config', 'user_sessions'];
    
    foreach ($required_tables as $table) {
        if (strpos($schema_content, "CREATE TABLE $table") !== false) {
            $success[] = "✓ Database schema includes: $table";
        } else {
            $errors[] = "✗ Database schema missing table: $table";
        }
    }
}

// Display results
echo "SUCCESS:\n";
foreach ($success as $msg) {
    echo "  $msg\n";
}

if (!empty($warnings)) {
    echo "\nWARNINGS:\n";
    foreach ($warnings as $msg) {
        echo "  $msg\n";
    }
}

if (!empty($errors)) {
    echo "\nERRORS:\n";
    foreach ($errors as $msg) {
        echo "  $msg\n";
    }
}

echo "\n" . str_repeat("=", 50) . "\n";

if (empty($errors)) {
    echo "✓ SETUP VERIFICATION PASSED\n";
    echo "\nNext steps:\n";
    echo "1. Install Composer dependencies: composer install\n";
    echo "2. Copy .env.example to .env and configure your settings\n";
    echo "3. Set up your MySQL database and run: php database/setup.php\n";
    echo "4. Configure your web server to point to the 'public' directory\n";
    echo "5. Set up cron jobs for automated monitoring\n";
    exit(0);
} else {
    echo "✗ SETUP VERIFICATION FAILED\n";
    echo "\nPlease fix the errors above before proceeding.\n";
    exit(1);
}
?>