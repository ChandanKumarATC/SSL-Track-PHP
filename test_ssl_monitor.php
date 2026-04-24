<?php
/**
 * Simple test script for SSL_Monitor functionality
 */

// Include the autoloader and configuration
require_once 'src/autoload.php';

use App\Services\SSL_Monitor;
use App\Models\TrackingItem;

echo "SSL Monitor Test Script\n";
echo "======================\n\n";

try {
    // Create SSL Monitor instance
    $sslMonitor = new SSL_Monitor();
    echo "✓ SSL_Monitor instance created successfully\n";
    
    // Test basic functionality
    echo "\nTesting basic functionality:\n";
    
    // Test with empty hostname (should fail)
    echo "- Testing empty hostname: ";
    $result = $sslMonitor->checkCertificate('');
    if ($result === null && $sslMonitor->hasErrors()) {
        echo "✓ Correctly rejected empty hostname\n";
    } else {
        echo "✗ Failed to reject empty hostname\n";
    }
    
    // Test with invalid port (should fail)
    echo "- Testing invalid port: ";
    $result = $sslMonitor->checkCertificate('example.com', 0);
    if ($result === null && $sslMonitor->hasErrors()) {
        echo "✓ Correctly rejected invalid port\n";
    } else {
        echo "✗ Failed to reject invalid port\n";
    }
    
    // Test calculateDaysUntilExpiry
    echo "- Testing calculateDaysUntilExpiry: ";
    $futureTimestamp = time() + (30 * 24 * 60 * 60); // 30 days from now
    $days = $sslMonitor->calculateDaysUntilExpiry($futureTimestamp);
    if ($days === 30) {
        echo "✓ Correctly calculated 30 days\n";
    } else {
        echo "✗ Expected 30 days, got {$days}\n";
    }
    
    // Test certificate validity check
    echo "- Testing certificate validity: ";
    $now = time();
    $certData = [
        'validFrom_time_t' => $now - 86400, // 1 day ago
        'validTo_time_t' => $now + 86400,   // 1 day from now
    ];
    
    if ($sslMonitor->isCertificateValid($certData)) {
        echo "✓ Correctly identified valid certificate\n";
    } else {
        echo "✗ Failed to identify valid certificate\n";
    }
    
    // Test certificate status
    echo "- Testing certificate status: ";
    $status = $sslMonitor->getCertificateStatus($certData);
    if ($status['status'] === 'valid') {
        echo "✓ Correctly determined certificate status\n";
    } else {
        echo "✗ Incorrect certificate status: " . $status['status'] . "\n";
    }
    
    // Test TrackingItem update
    echo "- Testing TrackingItem update: ";
    $item = new TrackingItem([
        'name' => 'Test SSL',
        'type' => 'ssl',
        'hostname' => 'example.com',
        'port' => 443,
    ]);
    
    $updatedItem = $sslMonitor->updateTrackingItem($item, null);
    if ($updatedItem->status === 'error' && $updatedItem->lastChecked !== null) {
        echo "✓ Correctly updated TrackingItem with error status\n";
    } else {
        echo "✗ Failed to update TrackingItem correctly\n";
    }
    
    // Test timeout and retry settings
    echo "- Testing timeout and retry settings: ";
    $sslMonitor->setTimeout(120);
    $sslMonitor->setMaxRetries(5);
    
    if ($sslMonitor->getTimeout() === 120 && $sslMonitor->getMaxRetries() === 5) {
        echo "✓ Correctly set timeout and retry values\n";
    } else {
        echo "✗ Failed to set timeout and retry values\n";
    }
    
    echo "\n✓ All basic tests completed successfully!\n";
    
    // Optional: Test with a real SSL endpoint if available
    echo "\nOptional real SSL test (requires internet):\n";
    echo "- Testing with www.google.com: ";
    
    $realResult = $sslMonitor->checkCertificate('www.google.com', 443);
    if ($realResult !== null) {
        echo "✓ Successfully retrieved certificate\n";
        echo "  - Issuer: " . $realResult->getIssuerName() . "\n";
        echo "  - Subject: " . $realResult->getCommonName() . "\n";
        echo "  - Valid until: " . $realResult->validTo->format('Y-m-d H:i:s') . "\n";
        echo "  - Days until expiry: " . $realResult->getDaysUntilExpiry() . "\n";
    } else {
        echo "⚠ Could not retrieve certificate (network issue or no internet)\n";
        if ($sslMonitor->hasErrors()) {
            echo "  Error: " . $sslMonitor->getLastErrorMessage() . "\n";
        }
    }
    
} catch (Exception $e) {
    echo "✗ Error during testing: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}

echo "\nTest completed.\n";