<?php
/**
 * Database Setup Script
 * 
 * This script sets up the database schema and initial configuration.
 * Run this script after creating the database to initialize all tables.
 */

require_once __DIR__ . '/../config/config.php';

echo "SSL & Domain Expiry Tracker - Database Setup\n";
echo "============================================\n\n";

try {
    // Create database connection without specifying database name first
    $dsn = "mysql:host=" . DB_HOST . ";charset=" . DB_CHARSET;
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    
    echo "Connected to MySQL server successfully.\n";
    
    // Create database if it doesn't exist
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "Database '" . DB_NAME . "' created or already exists.\n";
    
    // Switch to the database
    $pdo->exec("USE `" . DB_NAME . "`");
    echo "Using database '" . DB_NAME . "'.\n\n";
    
    // Read and execute schema file
    $schema = file_get_contents(__DIR__ . '/schema.sql');
    if ($schema === false) {
        throw new Exception("Could not read schema.sql file");
    }
    
    // Split schema into individual statements
    $statements = array_filter(
        array_map('trim', explode(';', $schema)),
        function($stmt) {
            return !empty($stmt) && !preg_match('/^--/', $stmt);
        }
    );
    
    echo "Executing database schema...\n";
    foreach ($statements as $statement) {
        if (trim($statement)) {
            try {
                $pdo->exec($statement);
                // Extract table name from CREATE TABLE statements for progress
                if (preg_match('/CREATE TABLE\s+(\w+)/i', $statement, $matches)) {
                    echo "  ✓ Created table: " . $matches[1] . "\n";
                } elseif (preg_match('/CREATE VIEW\s+(\w+)/i', $statement, $matches)) {
                    echo "  ✓ Created view: " . $matches[1] . "\n";
                } elseif (preg_match('/INSERT INTO\s+(\w+)/i', $statement, $matches)) {
                    echo "  ✓ Inserted data into: " . $matches[1] . "\n";
                }
            } catch (PDOException $e) {
                // Skip errors for statements that might already exist
                if (strpos($e->getMessage(), 'already exists') === false) {
                    echo "  ⚠ Warning: " . $e->getMessage() . "\n";
                }
            }
        }
    }
    
    echo "\nDatabase setup completed successfully!\n";
    echo "\nNext steps:\n";
    echo "1. Configure your environment variables (DB_HOST, DB_USER, DB_PASS)\n";
    echo "2. Set up your SMTP credentials for email notifications\n";
    echo "3. Run 'composer install' to install dependencies\n";
    echo "4. Configure your web server to point to the 'public' directory\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "\nPlease check your database configuration and try again.\n";
    exit(1);
}
?>