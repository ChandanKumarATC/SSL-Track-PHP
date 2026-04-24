<?php
/**
 * SSL & Domain Expiry Tracker - Domain Monitor Demo
 * 
 * Demonstration script for the Domain_Monitor service.
 * Shows how to use the Domain_Monitor to check domain expiration dates.
 */

require_once __DIR__ . '/src/autoload.php';
require_once __DIR__ . '/config/config.php';

use App\Services\Domain_Monitor;
use App\Models\TrackingItem;

echo "=== SSL & Domain Expiry Tracker - Domain Monitor Demo ===\n\n";

// Create Domain_Monitor instance
$domainMonitor = new Domain_Monitor();

// Test domains to check
$testDomains = [
    'example.com',
    'example.org',
    'google.com',
    'github.com',
    'stackoverflow.com'
];

echo "Testing Domain Monitor with sample domains...\n\n";

foreach ($testDomains as $domain) {
    echo "Checking domain: {$domain}\n";
    echo str_repeat('-', 50) . "\n";
    
    $startTime = microtime(true);
    $domainInfo = $domainMonitor->checkDomain($domain);
    $endTime = microtime(true);
    
    $lookupTime = round(($endTime - $startTime) * 1000, 2);
    
    if ($domainInfo !== null) {
        echo "✓ Domain lookup successful ({$lookupTime}ms)\n";
        echo "  Domain: {$domainInfo->domain}\n";
        echo "  Registrar: " . ($domainInfo->registrar ?? 'Unknown') . "\n";
        echo "  Expiry Date: " . ($domainInfo->expiryDate ? $domainInfo->expiryDate->format('Y-m-d H:i:s') : 'Unknown') . "\n";
        echo "  Registration Date: " . ($domainInfo->registrationDate ? $domainInfo->registrationDate->format('Y-m-d H:i:s') : 'Unknown') . "\n";
        echo "  Status: {$domainInfo->status}\n";
        echo "  TLD: {$domainInfo->getTLD()}\n";
        echo "  Name Servers: " . (empty($domainInfo->nameServers) ? 'None found' : implode(', ', array_slice($domainInfo->nameServers, 0, 3))) . "\n";
        
        if ($domainInfo->expiryDate) {
            $daysUntilExpiry = $domainInfo->getDaysUntilExpiry();
            if ($daysUntilExpiry !== null) {
                if ($daysUntilExpiry < 0) {
                    echo "  ⚠️  Domain expired " . abs($daysUntilExpiry) . " days ago\n";
                } elseif ($daysUntilExpiry <= DOMAIN_EXPIRY_WARNING_DAYS) {
                    echo "  ⚠️  Domain expires in {$daysUntilExpiry} days (WARNING)\n";
                } else {
                    echo "  ✓ Domain expires in {$daysUntilExpiry} days\n";
                }
            }
        }
        
        // Show validation status
        $validationStatus = $domainInfo->getValidationStatus();
        echo "  Validation Status: {$validationStatus['status']} - {$validationStatus['message']}\n";
        
        if (!empty($domainInfo->statusCodes)) {
            echo "  Status Codes: " . implode(', ', $domainInfo->statusCodes) . "\n";
        }
        
    } else {
        echo "✗ Domain lookup failed ({$lookupTime}ms)\n";
        
        if ($domainMonitor->hasErrors()) {
            $errors = $domainMonitor->getLastErrors();
            foreach ($errors as $error) {
                echo "  Error: {$error['message']}\n";
            }
        }
    }
    
    echo "\n";
}

// Test with TrackingItem integration
echo "Testing TrackingItem integration...\n";
echo str_repeat('=', 50) . "\n";

$trackingItems = [
    new TrackingItem([
        'name' => 'Example Domain',
        'type' => 'domain',
        'hostname' => 'example.com',
        'admin_emails' => ['admin@example.com']
    ]),
    new TrackingItem([
        'name' => 'Google Domain',
        'type' => 'domain',
        'hostname' => 'google.com',
        'admin_emails' => ['admin@google.com']
    ]),
    new TrackingItem([
        'name' => 'SSL Certificate', // This should be skipped
        'type' => 'ssl',
        'hostname' => 'example.com'
    ])
];

$results = $domainMonitor->batchCheckDomains($trackingItems);

echo "Batch check results:\n";
foreach ($results as $i => $result) {
    $item = $result['item'];
    $domainInfo = $result['domain'];
    $errors = $result['errors'];
    
    echo "\n" . ($i + 1) . ". {$item->name} ({$item->hostname})\n";
    echo "   Status: {$item->status}\n";
    echo "   Last Checked: " . ($item->lastChecked ? $item->lastChecked->format('Y-m-d H:i:s') : 'Never') . "\n";
    
    if ($domainInfo !== null) {
        echo "   Expiry Date: " . ($domainInfo->expiryDate ? $domainInfo->expiryDate->format('Y-m-d H:i:s') : 'Unknown') . "\n";
        echo "   Registrar: " . ($domainInfo->registrar ?? 'Unknown') . "\n";
        
        if ($domainInfo->expiryDate) {
            $daysUntilExpiry = $domainInfo->getDaysUntilExpiry();
            if ($daysUntilExpiry !== null) {
                echo "   Days Until Expiry: {$daysUntilExpiry}\n";
            }
        }
    }
    
    if (!empty($errors)) {
        echo "   Errors:\n";
        foreach ($errors as $error) {
            echo "     - {$error['message']}\n";
        }
    }
    
    if ($item->errorMessage) {
        echo "   Error Message: {$item->errorMessage}\n";
    }
}

// Test WHOIS server information
echo "\n\nWHOIS Server Information:\n";
echo str_repeat('=', 50) . "\n";

$whoisServers = $domainMonitor->getWhoisServers();
$commonTLDs = ['com', 'org', 'net', 'info', 'biz', 'us', 'uk', 'ca', 'de', 'fr'];

foreach ($commonTLDs as $tld) {
    if (isset($whoisServers[$tld])) {
        echo ".{$tld}: {$whoisServers[$tld]}\n";
    }
}

// Test configuration
echo "\n\nConfiguration:\n";
echo str_repeat('=', 50) . "\n";
echo "Timeout: {$domainMonitor->getTimeout()} seconds\n";
echo "Max Retries: {$domainMonitor->getMaxRetries()}\n";
echo "Domain Expiry Warning Days: " . DOMAIN_EXPIRY_WARNING_DAYS . "\n";
echo "WHOIS Timeout: " . WHOIS_TIMEOUT . " seconds\n";

// Test invalid domain
echo "\n\nTesting invalid domain handling...\n";
echo str_repeat('=', 50) . "\n";

$invalidDomains = [
    'invalid-domain-name',
    '',
    'domain.invalidtld',
    'this-domain-should-not-exist-12345.com'
];

foreach ($invalidDomains as $invalidDomain) {
    echo "Testing: '{$invalidDomain}'\n";
    $result = $domainMonitor->checkDomain($invalidDomain);
    
    if ($result === null) {
        echo "  ✓ Correctly rejected invalid domain\n";
        if ($domainMonitor->hasErrors()) {
            echo "  Error: " . $domainMonitor->getLastErrorMessage() . "\n";
        }
    } else {
        echo "  ✗ Unexpectedly accepted invalid domain\n";
    }
    echo "\n";
}

echo "\n=== Demo completed ===\n";