<?php
/**
 * SSL & Domain Expiry Tracker - Autoloader
 * 
 * Simple PSR-4 compatible autoloader for the application classes.
 */

spl_autoload_register(function ($className) {
    // Remove the App namespace prefix if present
    $className = ltrim($className, '\\');
    if (strpos($className, 'App\\') === 0) {
        $className = substr($className, 4);
    }
    
    // Convert namespace separators to directory separators
    $classFile = str_replace('\\', DIRECTORY_SEPARATOR, $className) . '.php';
    
    // Build the full path
    $fullPath = __DIR__ . DIRECTORY_SEPARATOR . $classFile;
    
    // Include the file if it exists
    if (file_exists($fullPath)) {
        require_once $fullPath;
        return true;
    }
    
    return false;
});

// Also include the Database class from the database directory
require_once __DIR__ . '/../database/Database.php';

// Include configuration
require_once __DIR__ . '/../config/config.php';