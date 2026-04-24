<?php
/**
 * Simple test script to verify the models work correctly
 */

// Include autoloader
require_once 'src/autoload.php';

use App\Models\TrackingItem;
use App\Models\CertificateInfo;
use App\Models\DomainInfo;
use App\Utils\Validator;

echo "Testing SSL & Domain Expiry Tracker Models\n";
echo "==========================================\n\n";

// Test TrackingItem
echo "1. Testing TrackingItem Model:\n";
try {
    $item = new TrackingItem([
        'name' => 'Test Domain',
        'type' => 'domain',
        'hostname' => 'example.com',
        'admin_emails' => ['admin@example.com'],
        'status' => 'active'
    ]);
    
    echo "✓ TrackingItem created successfully\n";
    echo "  Name: {$item->name}\n";
    echo "  Type: {$item->type}\n";
    echo "  Hostname: {$item->hostname}\n";
    echo "  Admin Emails: " . json_encode($item->adminEmails) . "\n";
    
    // Test validation
    $errors = $item->validate();
    if (empty($errors)) {
        echo "✓ TrackingItem validation passed\n";
    } else {
        echo "✗ TrackingItem validation failed: " . implode(', ', $errors) . "\n";
    }
    
} catch (Exception $e) {
    echo "✗ TrackingItem test failed: " . $e->getMessage() . "\n";
}

echo "\n";

// Test CertificateInfo
echo "2. Testing CertificateInfo Model:\n";
try {
    $certData = [
        'issuer' => ['CN' => 'Test CA', 'O' => 'Test Organization'],
        'subject' => ['CN' => 'example.com', 'O' => 'Example Corp'],
        'validFrom_time_t' => time(),
        'validTo_time_t' => time() + (365 * 24 * 60 * 60), // 1 year from now
        'extensions' => [
            'subjectAltName' => 'DNS:example.com, DNS:*.example.com'
        ]
    ];
    
    $cert = new CertificateInfo($certData);
    
    echo "✓ CertificateInfo created successfully\n";
    echo "  Issuer: {$cert->issuer}\n";
    echo "  Subject: {$cert->subject}\n";
    echo "  Valid From: " . $cert->validFrom->format('Y-m-d H:i:s') . "\n";
    echo "  Valid To: " . $cert->validTo->format('Y-m-d H:i:s') . "\n";
    echo "  Is Wildcard: " . ($cert->isWildcard ? 'Yes' : 'No') . "\n";
    echo "  Common Name: " . $cert->getCommonName() . "\n";
    
    // Test validation
    $errors = $cert->validate();
    if (empty($errors)) {
        echo "✓ CertificateInfo validation passed\n";
    } else {
        echo "✗ CertificateInfo validation failed: " . implode(', ', $errors) . "\n";
    }
    
} catch (Exception $e) {
    echo "✗ CertificateInfo test failed: " . $e->getMessage() . "\n";
}

echo "\n";

// Test DomainInfo
echo "3. Testing DomainInfo Model:\n";
try {
    $domainData = [
        'domain' => 'example.com',
        'registrar' => 'Test Registrar',
        'expiry_date' => (new DateTime())->modify('+30 days')->format('Y-m-d H:i:s'),
        'registration_date' => (new DateTime())->modify('-365 days')->format('Y-m-d H:i:s'),
        'status' => 'active',
        'name_servers' => ['ns1.example.com', 'ns2.example.com']
    ];
    
    $domain = new DomainInfo($domainData);
    
    echo "✓ DomainInfo created successfully\n";
    echo "  Domain: {$domain->domain}\n";
    echo "  Registrar: {$domain->registrar}\n";
    echo "  Expiry Date: " . ($domain->expiryDate ? $domain->expiryDate->format('Y-m-d H:i:s') : 'N/A') . "\n";
    echo "  Registration Date: " . ($domain->registrationDate ? $domain->registrationDate->format('Y-m-d H:i:s') : 'N/A') . "\n";
    echo "  Status: {$domain->status}\n";
    echo "  Name Servers: " . implode(', ', $domain->nameServers) . "\n";
    echo "  Days Until Expiry: " . $domain->getDaysUntilExpiry() . "\n";
    
    // Test validation
    $errors = $domain->validate();
    if (empty($errors)) {
        echo "✓ DomainInfo validation passed\n";
    } else {
        echo "✗ DomainInfo validation failed: " . implode(', ', $errors) . "\n";
    }
    
} catch (Exception $e) {
    echo "✗ DomainInfo test failed: " . $e->getMessage() . "\n";
}

echo "\n";

// Test Validator
echo "4. Testing Validator Utility:\n";
try {
    // Test domain validation
    $domainResult = Validator::validateDomain('https://www.example.com:8080/path');
    echo "✓ Domain validation test:\n";
    echo "  Input: 'https://www.example.com:8080/path'\n";
    echo "  Output: '{$domainResult['domain']}'\n";
    echo "  Valid: " . ($domainResult['valid'] ? 'Yes' : 'No') . "\n";
    if (!empty($domainResult['errors'])) {
        echo "  Errors: " . implode(', ', $domainResult['errors']) . "\n";
    }
    
    // Test SSL endpoint validation
    $sslResult = Validator::validateSSLEndpoint('ssl.example.com:443', 443);
    echo "✓ SSL endpoint validation test:\n";
    echo "  Hostname: '{$sslResult['hostname']}'\n";
    echo "  Port: {$sslResult['port']}\n";
    echo "  Valid: " . ($sslResult['valid'] ? 'Yes' : 'No') . "\n";
    if (!empty($sslResult['errors'])) {
        echo "  Errors: " . implode(', ', $sslResult['errors']) . "\n";
    }
    
    // Test email validation
    $emailResult = Validator::validateEmail('  TEST@EXAMPLE.COM  ');
    echo "✓ Email validation test:\n";
    echo "  Input: '  TEST@EXAMPLE.COM  '\n";
    echo "  Output: '{$emailResult['email']}'\n";
    echo "  Valid: " . ($emailResult['valid'] ? 'Yes' : 'No') . "\n";
    if (!empty($emailResult['errors'])) {
        echo "  Errors: " . implode(', ', $emailResult['errors']) . "\n";
    }
    
    // Test tracking item data validation
    $trackingData = [
        'name' => 'Test SSL Certificate',
        'type' => 'ssl',
        'hostname' => 'secure.example.com',
        'port' => '443',
        'admin_emails' => ['admin@example.com', 'security@example.com'],
        'status' => 'active'
    ];
    
    $trackingResult = Validator::validateTrackingItemData($trackingData);
    echo "✓ Tracking item validation test:\n";
    echo "  Valid: " . ($trackingResult['valid'] ? 'Yes' : 'No') . "\n";
    if ($trackingResult['valid']) {
        echo "  Validated data: " . json_encode($trackingResult['data'], JSON_PRETTY_PRINT) . "\n";
    } else {
        echo "  Errors: " . implode(', ', $trackingResult['errors']) . "\n";
    }
    
} catch (Exception $e) {
    echo "✗ Validator test failed: " . $e->getMessage() . "\n";
}

echo "\n";

// Test input sanitization
echo "5. Testing Input Sanitization:\n";
try {
    $dirtyData = [
        'name' => "Test\0Name\x01With\x02Control\x03Chars",
        'hostname' => "  example.com  ",
        'admin_emails' => ['test@example.com', '  admin@test.com  ']
    ];
    
    $sanitized = TrackingItem::sanitizeInput($dirtyData);
    
    echo "✓ Input sanitization test:\n";
    echo "  Original name: '" . addcslashes($dirtyData['name'], "\0..\37") . "'\n";
    echo "  Sanitized name: '{$sanitized['name']}'\n";
    echo "  Original hostname: '{$dirtyData['hostname']}'\n";
    echo "  Sanitized hostname: '{$sanitized['hostname']}'\n";
    
} catch (Exception $e) {
    echo "✗ Input sanitization test failed: " . $e->getMessage() . "\n";
}

echo "\n";
echo "==========================================\n";
echo "All model tests completed!\n";
?>