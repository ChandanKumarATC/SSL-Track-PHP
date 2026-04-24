<?php
/**
 * SSL Monitor Demonstration Script
 * 
 * Demonstrates the SSL_Monitor functionality with real examples.
 */

// Include the autoloader and configuration
require_once 'src/autoload.php';

use App\Services\SSL_Monitor;
use App\Models\TrackingItem;
use App\Models\CertificateInfo;

echo "SSL Monitor Demonstration\n";
echo "========================\n\n";

try {
    // Create SSL Monitor instance
    $sslMonitor = new SSL_Monitor(30, 3, 2); // 30s timeout, 3 retries, 2s delay
    echo "✓ SSL_Monitor created with custom settings\n";
    echo "  - Timeout: {$sslMonitor->getTimeout()} seconds\n";
    echo "  - Max retries: {$sslMonitor->getMaxRetries()}\n\n";
    
    // Demonstrate input validation
    echo "1. Input Validation Tests:\n";
    echo "   ------------------------\n";
    
    // Test empty hostname
    echo "   Testing empty hostname: ";
    $result = $sslMonitor->checkCertificate('');
    echo ($result === null && $sslMonitor->hasErrors()) ? "✓ PASS\n" : "✗ FAIL\n";
    
    // Test invalid port
    echo "   Testing invalid port: ";
    $result = $sslMonitor->checkCertificate('example.com', -1);
    echo ($result === null && $sslMonitor->hasErrors()) ? "✓ PASS\n" : "✗ FAIL\n";
    
    // Demonstrate certificate data parsing with mock data
    echo "\n2. Certificate Data Processing:\n";
    echo "   -----------------------------\n";
    
    // Create mock certificate data (simulating what OpenSSL would return)
    $mockCertData = [
        'issuer' => [
            'CN' => 'Let\'s Encrypt Authority X3',
            'O' => 'Let\'s Encrypt',
            'C' => 'US'
        ],
        'subject' => [
            'CN' => 'example.com',
            'O' => 'Example Corporation'
        ],
        'validFrom_time_t' => time() - (30 * 24 * 60 * 60), // 30 days ago
        'validTo_time_t' => time() + (60 * 24 * 60 * 60),   // 60 days from now
        'extensions' => [
            'subjectAltName' => 'DNS:example.com, DNS:www.example.com, DNS:*.example.com'
        ],
        'fingerprint' => 'sha256:1234567890abcdef1234567890abcdef12345678',
        'serialNumber' => '0x123456789abcdef',
        'signatureTypeSN' => 'RSA-SHA256'
    ];
    
    $certInfo = new CertificateInfo($mockCertData);
    echo "   ✓ Certificate parsed successfully\n";
    echo "   - Issuer: {$certInfo->getIssuerName()}\n";
    echo "   - Subject: {$certInfo->getCommonName()}\n";
    echo "   - Valid from: {$certInfo->validFrom->format('Y-m-d H:i:s')}\n";
    echo "   - Valid to: {$certInfo->validTo->format('Y-m-d H:i:s')}\n";
    echo "   - Days until expiry: {$certInfo->getDaysUntilExpiry()}\n";
    echo "   - Is wildcard: " . ($certInfo->isWildcard ? 'Yes' : 'No') . "\n";
    echo "   - Covered domains: " . implode(', ', $certInfo->getCoveredDomains()) . "\n";
    
    // Demonstrate status calculation
    echo "\n3. Certificate Status Analysis:\n";
    echo "   -----------------------------\n";
    
    $statusInfo = $certInfo->getValidationStatus();
    echo "   - Status: {$statusInfo['status']}\n";
    echo "   - Message: {$statusInfo['message']}\n";
    echo "   - Days until expiry: {$statusInfo['days_until_expiry']}\n";
    
    // Demonstrate TrackingItem integration
    echo "\n4. TrackingItem Integration:\n";
    echo "   -------------------------\n";
    
    $trackingItem = new TrackingItem([
        'name' => 'Example SSL Certificate',
        'type' => 'ssl',
        'hostname' => 'example.com',
        'port' => 443,
        'admin_emails' => ['admin@example.com', 'security@example.com']
    ]);
    
    echo "   ✓ TrackingItem created\n";
    echo "   - Name: {$trackingItem->name}\n";
    echo "   - Type: {$trackingItem->type}\n";
    echo "   - Hostname: {$trackingItem->hostname}\n";
    echo "   - Port: {$trackingItem->port}\n";
    
    // Update tracking item with certificate info
    $updatedItem = $sslMonitor->updateTrackingItem($trackingItem, $certInfo);
    echo "   ✓ TrackingItem updated with certificate info\n";
    echo "   - Status: {$updatedItem->status}\n";
    echo "   - Last checked: {$updatedItem->lastChecked->format('Y-m-d H:i:s')}\n";
    echo "   - Expiry date: {$updatedItem->expiryDate->format('Y-m-d H:i:s')}\n";
    echo "   - Status color: {$updatedItem->getStatusColor()}\n";
    
    // Demonstrate different certificate scenarios
    echo "\n5. Different Certificate Scenarios:\n";
    echo "   ---------------------------------\n";
    
    $scenarios = [
        [
            'name' => 'Valid Certificate (30+ days)',
            'validTo' => time() + (45 * 24 * 60 * 60),
            'expectedStatus' => 'active'
        ],
        [
            'name' => 'Expiring Soon (< 7 days)',
            'validTo' => time() + (3 * 24 * 60 * 60),
            'expectedStatus' => 'warning'
        ],
        [
            'name' => 'Expired Certificate',
            'validTo' => time() - (5 * 24 * 60 * 60),
            'expectedStatus' => 'expired'
        ]
    ];
    
    foreach ($scenarios as $scenario) {
        $scenarioCertData = $mockCertData;
        $scenarioCertData['validTo_time_t'] = $scenario['validTo'];
        
        $scenarioCert = new CertificateInfo($scenarioCertData);
        $scenarioItem = new TrackingItem([
            'name' => $scenario['name'],
            'type' => 'ssl',
            'hostname' => 'example.com',
            'port' => 443
        ]);
        
        $updatedScenarioItem = $sslMonitor->updateTrackingItem($scenarioItem, $scenarioCert);
        
        echo "   - {$scenario['name']}:\n";
        echo "     Status: {$updatedScenarioItem->status}\n";
        echo "     Days until expiry: {$scenarioCert->getDaysUntilExpiry()}\n";
        echo "     Color indicator: {$updatedScenarioItem->getStatusColor()}\n";
    }
    
    // Demonstrate batch processing
    echo "\n6. Batch Processing:\n";
    echo "   -----------------\n";
    
    $batchItems = [
        new TrackingItem([
            'name' => 'SSL Site 1',
            'type' => 'ssl',
            'hostname' => 'site1.example.com',
            'port' => 443
        ]),
        new TrackingItem([
            'name' => 'SSL Site 2',
            'type' => 'ssl',
            'hostname' => 'site2.example.com',
            'port' => 8443
        ]),
        new TrackingItem([
            'name' => 'Domain Site', // This should be ignored
            'type' => 'domain',
            'hostname' => 'domain.example.com'
        ])
    ];
    
    $batchResults = $sslMonitor->batchCheckCertificates($batchItems);
    echo "   ✓ Batch processing completed\n";
    echo "   - Processed {" . count($batchResults) . "} SSL items (ignored domain items)\n";
    
    foreach ($batchResults as $index => $result) {
        $item = $result['item'];
        echo "   - Item " . ($index + 1) . ": {$item->name} -> Status: {$item->status}\n";
    }
    
    // Demonstrate error handling
    echo "\n7. Error Handling:\n";
    echo "   ---------------\n";
    
    // Test with invalid hostname
    $errorResult = $sslMonitor->checkCertificate('invalid-hostname-12345.invalid');
    echo "   ✓ Error handling test completed\n";
    echo "   - Result: " . ($errorResult === null ? 'null (expected)' : 'unexpected result') . "\n";
    echo "   - Has errors: " . ($sslMonitor->hasErrors() ? 'Yes' : 'No') . "\n";
    
    if ($sslMonitor->hasErrors()) {
        echo "   - Last error: {$sslMonitor->getLastErrorMessage()}\n";
        echo "   - Total errors: " . count($sslMonitor->getLastErrors()) . "\n";
    }
    
    // Test error handling with TrackingItem update
    $errorItem = new TrackingItem([
        'name' => 'Error Test SSL',
        'type' => 'ssl',
        'hostname' => 'error-test.invalid',
        'port' => 443
    ]);
    
    $errorUpdatedItem = $sslMonitor->updateTrackingItem($errorItem, null);
    echo "   ✓ TrackingItem error handling test\n";
    echo "   - Status: {$errorUpdatedItem->status}\n";
    echo "   - Error message: {$errorUpdatedItem->errorMessage}\n";
    
    echo "\n✅ SSL Monitor demonstration completed successfully!\n";
    echo "\nKey Features Demonstrated:\n";
    echo "- ✓ Input validation and error handling\n";
    echo "- ✓ Certificate data parsing and analysis\n";
    echo "- ✓ Status determination (valid/warning/expired)\n";
    echo "- ✓ TrackingItem integration and updates\n";
    echo "- ✓ Batch processing capabilities\n";
    echo "- ✓ Comprehensive error handling\n";
    echo "- ✓ Configurable timeout and retry settings\n";
    
} catch (Exception $e) {
    echo "❌ Error during demonstration: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}

echo "\nDemonstration completed.\n";