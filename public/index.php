<?php
/**
 * SSL & Domain Expiry Tracker - Main Entry Point
 * 
 * This is the main entry point for the web application.
 * All web requests are routed through this file.
 */

// Start session for authentication
session_start();

// Set error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Include autoloader
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/config.php';

// Simple routing for now - will be expanded later
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);

switch ($path) {
    case '/':
    case '/dashboard':
        echo "<h1>SSL & Domain Expiry Tracker</h1>";
        echo "<p>Dashboard coming soon...</p>";
        break;
    
    default:
        http_response_code(404);
        echo "<h1>404 - Page Not Found</h1>";
        break;
}
?>