<?php
/**
 * SSL & Domain Expiry Tracker - SSL_Monitor Integration Tests
 * 
 * Integration tests for SSL_Monitor with database and repository classes.
 */

use PHPUnit\Framework\TestCase;
use App\Services\SSL_Monitor;
use App\Models\TrackingItem;
use App\Models\TrackingItemRepository;
use App\Models\SSLCertificateRepository;
use App\Models\CertificateInfo;

class SSL_MonitorIntegrationTest extends TestCase {
    private SSL_Monitor $sslMonitor;
    private TrackingItemRepository $trackingRepo;
    private SSLCertificateRepository $sslRepo;
    private Database $database;
    
    protected function setUp(): void {
        $this->sslMonitor = new SSL_Monitor();
        
        // Use in-memory SQLite for testing
        $this->database = new Database([
            'host' => ':memory:',
            'dbname' => 'test',
            'username' => '',
            'password' => '',
            'driver' => 'sqlite'
        ]);
        
        $this->trackingRepo = new TrackingItemRepository($this->database);
        $this->sslRepo = new SSLCertificateRepository($this->database);
        
        // Create test tables
        $this->createTestTables();
    }
    
    protected function tearDown(): void {
        // Clean up is automatic with in-memory database
    }
    
    /**
     * Create test database tables
     */
    private function createTestTables(): void {
        $sql = "
            CREATE TABLE tracking_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(10) NOT NULL,
                hostname VARCHAR(255) NOT NULL,
                port INTEGER DEFAULT 443,
                registrar VARCHAR(255),
                admin_emails TEXT,
                expiry_date DATETIME,
                last_checked DATETIME,
                status VARCHAR(20) DEFAULT 'active',
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE ssl_certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tracking_item_id INTEGER NOT NULL,
                issuer VARCHAR(255),
                subject VARCHAR(255),
                is_wildcard BOOLEAN DEFAULT FALSE,
                certificate_path VARCHAR(500),
                private_key_path VARCHAR(500),
                chain_path VARCHAR(500),
                auto_renew BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (tracking_item_id) REFERENCES tracking_items(id) ON DELETE CASCADE
            );
        ";
        
        $this->database->exec($sql);
    }
    
    /**
     * Test complete SSL monitoring workflow
     */
    public function testCompleteSSLMonitoringWorkflow(): void {
        // Create a test SSL tracking item
        $trackingItem = new TrackingItem([
            'name' => 'Test SSL Certificate',
            'type' => 'ssl',
            'hostname' => 'example.com',
            'port' => 443,
            'admin_emails' => ['admin@example.com'],
        ]);
        
        // Save to database
        $savedItem = $this->trackingRepo->save($trackingItem);
        $this->assertNotNull($savedItem->id);
        
        // Simulate SSL certificate check (we'll create mock certificate data)
        $mockCertData = [
            'issuer' => ['CN' => 'Test CA', 'O' => 'Test Organization'],
            'subject' => ['CN' => 'example.com', 'O' => 'Example Corp'],
            'validFrom_time_t' => time() - 86400, // 1 day ago
            'validTo_time_t' => time() + (30 * 24 * 60 * 60), // 30 days from now
            'extensions' => [
                'subjectAltName' => 'DNS:example.com, DNS:www.example.com'
            ],
            'fingerprint' => 'abc123def456',
            'serialNumber' => '12345',
        ];
        
        $certInfo = new CertificateInfo($mockCertData);
        
        // Update tracking item with certificate info
        $updatedItem = $this->sslMonitor->updateTrackingItem($savedItem, $certInfo);
        
        // Verify the update
        $this->assertEquals('active', $updatedItem->status);
        $this->assertNull($updatedItem->errorMessage);
        $this->assertInstanceOf(DateTime::class, $updatedItem->lastChecked);
        $this->assertInstanceOf(DateTime::class, $updatedItem->expiryDate);
        
        // Save the updated item back to database
        $finalItem = $this->trackingRepo->save($updatedItem);
        
        // Verify it was saved correctly
        $retrievedItem = $this->trackingRepo->findById($finalItem->id);
        $this->assertNotNull($retrievedItem);
        $this->assertEquals('active', $retrievedItem->status);
        $this->assertNotNull($retrievedItem->expiryDate);
    }
    
    /**
     * Test SSL monitoring with error handling
     */
    public function testSSLMonitoringWithErrorHandling(): void {
        // Create a test SSL tracking item with invalid hostname
        $trackingItem = new TrackingItem([
            'name' => 'Invalid SSL Certificate',
            'type' => 'ssl',
            'hostname' => 'invalid-hostname-that-does-not-exist.invalid',
            'port' => 443,
        ]);
        
        // Save to database
        $savedItem = $this->trackingRepo->save($trackingItem);
        
        // Attempt SSL certificate check (should fail)
        $certInfo = $this->sslMonitor->checkCertificate($savedItem->hostname, $savedItem->port);
        
        // Update tracking item (should set error status)
        $updatedItem = $this->sslMonitor->updateTrackingItem($savedItem, $certInfo);
        
        // Verify error handling
        $this->assertEquals('error', $updatedItem->status);
        $this->assertNotNull($updatedItem->errorMessage);
        $this->assertInstanceOf(DateTime::class, $updatedItem->lastChecked);
        $this->assertNull($updatedItem->expiryDate);
        
        // Save and verify
        $finalItem = $this->trackingRepo->save($updatedItem);
        $retrievedItem = $this->trackingRepo->findById($finalItem->id);
        
        $this->assertEquals('error', $retrievedItem->status);
        $this->assertNotNull($retrievedItem->errorMessage);
    }
    
    /**
     * Test batch SSL certificate monitoring
     */
    public function testBatchSSLCertificateMonitoring(): void {
        // Create multiple SSL tracking items
        $items = [
            new TrackingItem([
                'name' => 'SSL Test 1',
                'type' => 'ssl',
                'hostname' => 'example1.com',
                'port' => 443,
            ]),
            new TrackingItem([
                'name' => 'SSL Test 2',
                'type' => 'ssl',
                'hostname' => 'example2.com',
                'port' => 443,
            ]),
            new TrackingItem([
                'name' => 'Domain Test', // This should be ignored
                'type' => 'domain',
                'hostname' => 'example.com',
            ]),
        ];
        
        // Save all items
        $savedItems = [];
        foreach ($items as $item) {
            $savedItems[] = $this->trackingRepo->save($item);
        }
        
        // Perform batch check
        $results = $this->sslMonitor->batchCheckCertificates($savedItems);
        
        // Should only process SSL items (2 out of 3)
        $this->assertCount(2, $results);
        
        foreach ($results as $result) {
            $this->assertArrayHasKey('item', $result);
            $this->assertArrayHasKey('certificate', $result);
            $this->assertArrayHasKey('errors', $result);
            
            $item = $result['item'];
            $this->assertEquals('ssl', $item->type);
            $this->assertInstanceOf(DateTime::class, $item->lastChecked);
        }
    }
    
    /**
     * Test SSL certificate status determination
     */
    public function testSSLCertificateStatusDetermination(): void {
        $now = time();
        
        // Test cases for different certificate statuses
        $testCases = [
            [
                'name' => 'Valid Certificate',
                'validTo' => $now + (30 * 24 * 60 * 60), // 30 days from now
                'expectedStatus' => 'active',
            ],
            [
                'name' => 'Expiring Soon Certificate',
                'validTo' => $now + (3 * 24 * 60 * 60), // 3 days from now
                'expectedStatus' => 'warning',
            ],
            [
                'name' => 'Expired Certificate',
                'validTo' => $now - (5 * 24 * 60 * 60), // 5 days ago
                'expectedStatus' => 'expired',
            ],
        ];
        
        foreach ($testCases as $testCase) {
            $trackingItem = new TrackingItem([
                'name' => $testCase['name'],
                'type' => 'ssl',
                'hostname' => 'example.com',
                'port' => 443,
            ]);
            
            $certInfo = new CertificateInfo([
                'issuer' => ['CN' => 'Test CA'],
                'subject' => ['CN' => 'example.com'],
                'validFrom_time_t' => $now - 86400,
                'validTo_time_t' => $testCase['validTo'],
            ]);
            
            $updatedItem = $this->sslMonitor->updateTrackingItem($trackingItem, $certInfo);
            
            $this->assertEquals(
                $testCase['expectedStatus'],
                $updatedItem->status,
                "Failed for test case: {$testCase['name']}"
            );
        }
    }
    
    /**
     * Test SSL monitoring logging
     */
    public function testSSLMonitoringLogging(): void {
        // Create a temporary log file for testing
        $logFile = sys_get_temp_dir() . '/ssl_monitor_test.log';
        
        // Override the LOG_DIR constant for this test
        if (!defined('LOG_DIR')) {
            define('LOG_DIR', sys_get_temp_dir());
        }
        
        // Test logging
        $this->sslMonitor->logActivity('example.com', 443, 'success', 'Certificate retrieved successfully');
        
        // Check if log file was created and contains expected content
        $expectedLogFile = LOG_DIR . '/ssl_monitor.log';
        
        if (file_exists($expectedLogFile)) {
            $logContent = file_get_contents($expectedLogFile);
            $this->assertStringContains('ssl_monitor', $logContent);
            $this->assertStringContains('example.com', $logContent);
            $this->assertStringContains('success', $logContent);
        }
        
        // Clean up
        if (file_exists($expectedLogFile)) {
            unlink($expectedLogFile);
        }
    }
    
    /**
     * Test SSL certificate validation edge cases
     */
    public function testSSLCertificateValidationEdgeCases(): void {
        // Test with empty hostname
        $result = $this->sslMonitor->checkCertificate('');
        $this->assertNull($result);
        $this->assertTrue($this->sslMonitor->hasErrors());
        
        // Test with invalid port ranges
        $result = $this->sslMonitor->checkCertificate('example.com', 0);
        $this->assertNull($result);
        
        $result = $this->sslMonitor->checkCertificate('example.com', 70000);
        $this->assertNull($result);
        
        // Test timeout and retry configuration
        $monitor = new SSL_Monitor(5, 2, 1); // Short timeout, few retries
        $this->assertEquals(5, $monitor->getTimeout());
        $this->assertEquals(2, $monitor->getMaxRetries());
        
        // Test minimum value enforcement
        $monitor->setTimeout(0);
        $monitor->setMaxRetries(0);
        $this->assertEquals(1, $monitor->getTimeout());
        $this->assertEquals(1, $monitor->getMaxRetries());
    }
}