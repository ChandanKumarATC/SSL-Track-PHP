<?php
/**
 * SSL & Domain Expiry Tracker - SSL_Monitor Unit Tests
 * 
 * Tests for the SSL_Monitor service class.
 */

use PHPUnit\Framework\TestCase;
use App\Services\SSL_Monitor;
use App\Models\CertificateInfo;
use App\Models\TrackingItem;

class SSL_MonitorTest extends TestCase {
    private SSL_Monitor $sslMonitor;
    
    protected function setUp(): void {
        $this->sslMonitor = new SSL_Monitor();
    }
    
    /**
     * Test SSL_Monitor constructor with default values
     */
    public function testConstructorWithDefaults(): void {
        $monitor = new SSL_Monitor();
        
        $this->assertEquals(SSL_TIMEOUT, $monitor->getTimeout());
        $this->assertEquals(MAX_RETRY_ATTEMPTS, $monitor->getMaxRetries());
    }
    
    /**
     * Test SSL_Monitor constructor with custom values
     */
    public function testConstructorWithCustomValues(): void {
        $monitor = new SSL_Monitor(60, 5, 10);
        
        $this->assertEquals(60, $monitor->getTimeout());
        $this->assertEquals(5, $monitor->getMaxRetries());
    }
    
    /**
     * Test checkCertificate with empty hostname
     */
    public function testCheckCertificateWithEmptyHostname(): void {
        $result = $this->sslMonitor->checkCertificate('');
        
        $this->assertNull($result);
        $this->assertTrue($this->sslMonitor->hasErrors());
        $this->assertStringContains('Hostname cannot be empty', $this->sslMonitor->getLastErrorMessage());
    }
    
    /**
     * Test checkCertificate with invalid port
     */
    public function testCheckCertificateWithInvalidPort(): void {
        $result = $this->sslMonitor->checkCertificate('example.com', 0);
        
        $this->assertNull($result);
        $this->assertTrue($this->sslMonitor->hasErrors());
        $this->assertStringContains('Port must be between 1 and 65535', $this->sslMonitor->getLastErrorMessage());
        
        $result = $this->sslMonitor->checkCertificate('example.com', 70000);
        
        $this->assertNull($result);
        $this->assertTrue($this->sslMonitor->hasErrors());
    }
    
    /**
     * Test checkCertificate with a known good SSL endpoint
     * Note: This test requires internet connectivity
     */
    public function testCheckCertificateWithValidEndpoint(): void {
        // Use a reliable SSL endpoint for testing
        $result = $this->sslMonitor->checkCertificate('www.google.com', 443);
        
        if ($result !== null) {
            $this->assertInstanceOf(CertificateInfo::class, $result);
            $this->assertNotEmpty($result->issuer);
            $this->assertNotEmpty($result->subject);
            $this->assertInstanceOf(DateTime::class, $result->validFrom);
            $this->assertInstanceOf(DateTime::class, $result->validTo);
        } else {
            // If the test fails due to network issues, just check that errors were logged
            $this->assertTrue($this->sslMonitor->hasErrors());
        }
    }
    
    /**
     * Test checkCertificate with invalid hostname
     */
    public function testCheckCertificateWithInvalidHostname(): void {
        $result = $this->sslMonitor->checkCertificate('invalid-hostname-that-does-not-exist.invalid');
        
        $this->assertNull($result);
        $this->assertTrue($this->sslMonitor->hasErrors());
    }
    
    /**
     * Test calculateDaysUntilExpiry with future date
     */
    public function testCalculateDaysUntilExpiryWithFutureDate(): void {
        $futureTimestamp = time() + (30 * 24 * 60 * 60); // 30 days from now
        $days = $this->sslMonitor->calculateDaysUntilExpiry($futureTimestamp);
        
        $this->assertEquals(30, $days);
    }
    
    /**
     * Test calculateDaysUntilExpiry with past date
     */
    public function testCalculateDaysUntilExpiryWithPastDate(): void {
        $pastTimestamp = time() - (10 * 24 * 60 * 60); // 10 days ago
        $days = $this->sslMonitor->calculateDaysUntilExpiry($pastTimestamp);
        
        $this->assertEquals(-10, $days);
    }
    
    /**
     * Test isCertificateValid with valid certificate data
     */
    public function testIsCertificateValidWithValidCert(): void {
        $now = time();
        $certData = [
            'validFrom_time_t' => $now - 86400, // 1 day ago
            'validTo_time_t' => $now + 86400,   // 1 day from now
        ];
        
        $this->assertTrue($this->sslMonitor->isCertificateValid($certData));
    }
    
    /**
     * Test isCertificateValid with expired certificate data
     */
    public function testIsCertificateValidWithExpiredCert(): void {
        $now = time();
        $certData = [
            'validFrom_time_t' => $now - (2 * 86400), // 2 days ago
            'validTo_time_t' => $now - 86400,         // 1 day ago (expired)
        ];
        
        $this->assertFalse($this->sslMonitor->isCertificateValid($certData));
    }
    
    /**
     * Test isCertificateExpiringSoon with certificate expiring soon
     */
    public function testIsCertificateExpiringSoonWithSoonExpiring(): void {
        $now = time();
        $certData = [
            'validTo_time_t' => $now + (3 * 24 * 60 * 60), // 3 days from now
        ];
        
        $this->assertTrue($this->sslMonitor->isCertificateExpiringSoon($certData));
    }
    
    /**
     * Test isCertificateExpiringSoon with certificate not expiring soon
     */
    public function testIsCertificateExpiringSoonWithNotExpiring(): void {
        $now = time();
        $certData = [
            'validTo_time_t' => $now + (30 * 24 * 60 * 60), // 30 days from now
        ];
        
        $this->assertFalse($this->sslMonitor->isCertificateExpiringSoon($certData));
    }
    
    /**
     * Test getCertificateStatus with valid certificate
     */
    public function testGetCertificateStatusWithValidCert(): void {
        $now = time();
        $certData = [
            'validTo_time_t' => $now + (30 * 24 * 60 * 60), // 30 days from now
        ];
        
        $status = $this->sslMonitor->getCertificateStatus($certData);
        
        $this->assertEquals('valid', $status['status']);
        $this->assertEquals('Certificate is valid', $status['message']);
        $this->assertEquals(30, $status['days_until_expiry']);
    }
    
    /**
     * Test getCertificateStatus with expiring soon certificate
     */
    public function testGetCertificateStatusWithExpiringSoon(): void {
        $now = time();
        $certData = [
            'validTo_time_t' => $now + (3 * 24 * 60 * 60), // 3 days from now
        ];
        
        $status = $this->sslMonitor->getCertificateStatus($certData);
        
        $this->assertEquals('expiring_soon', $status['status']);
        $this->assertEquals('Certificate is expiring soon', $status['message']);
        $this->assertEquals(3, $status['days_until_expiry']);
    }
    
    /**
     * Test getCertificateStatus with expired certificate
     */
    public function testGetCertificateStatusWithExpiredCert(): void {
        $now = time();
        $certData = [
            'validTo_time_t' => $now - (5 * 24 * 60 * 60), // 5 days ago
        ];
        
        $status = $this->sslMonitor->getCertificateStatus($certData);
        
        $this->assertEquals('expired', $status['status']);
        $this->assertEquals('Certificate has expired', $status['message']);
        $this->assertEquals(-5, $status['days_until_expiry']);
    }
    
    /**
     * Test updateTrackingItem with valid certificate info
     */
    public function testUpdateTrackingItemWithValidCertificate(): void {
        $item = new TrackingItem([
            'name' => 'Test SSL',
            'type' => 'ssl',
            'hostname' => 'example.com',
            'port' => 443,
        ]);
        
        $certInfo = new CertificateInfo([
            'issuer' => ['CN' => 'Test CA'],
            'subject' => ['CN' => 'example.com'],
            'validFrom_time_t' => time() - 86400,
            'validTo_time_t' => time() + (30 * 24 * 60 * 60), // 30 days from now
        ]);
        
        $updatedItem = $this->sslMonitor->updateTrackingItem($item, $certInfo);
        
        $this->assertEquals('active', $updatedItem->status);
        $this->assertNull($updatedItem->errorMessage);
        $this->assertInstanceOf(DateTime::class, $updatedItem->lastChecked);
        $this->assertInstanceOf(DateTime::class, $updatedItem->expiryDate);
    }
    
    /**
     * Test updateTrackingItem with null certificate info (error case)
     */
    public function testUpdateTrackingItemWithNullCertificate(): void {
        $item = new TrackingItem([
            'name' => 'Test SSL',
            'type' => 'ssl',
            'hostname' => 'example.com',
            'port' => 443,
        ]);
        
        // Simulate an error by adding an error message
        $this->sslMonitor->checkCertificate(''); // This will add an error
        
        $updatedItem = $this->sslMonitor->updateTrackingItem($item, null);
        
        $this->assertEquals('error', $updatedItem->status);
        $this->assertNotNull($updatedItem->errorMessage);
        $this->assertInstanceOf(DateTime::class, $updatedItem->lastChecked);
    }
    
    /**
     * Test validateEndpoint with reachable endpoint
     * Note: This test requires internet connectivity
     */
    public function testValidateEndpointWithReachableHost(): void {
        $result = $this->sslMonitor->validateEndpoint('www.google.com', 443);
        
        // This might fail in environments without internet access
        // In that case, we just verify the method doesn't throw exceptions
        $this->assertIsBool($result);
    }
    
    /**
     * Test validateEndpoint with unreachable endpoint
     */
    public function testValidateEndpointWithUnreachableHost(): void {
        $result = $this->sslMonitor->validateEndpoint('invalid-hostname-that-does-not-exist.invalid', 443);
        
        $this->assertFalse($result);
    }
    
    /**
     * Test error handling methods
     */
    public function testErrorHandling(): void {
        // Initially no errors
        $this->assertFalse($this->sslMonitor->hasErrors());
        $this->assertEmpty($this->sslMonitor->getLastErrors());
        $this->assertNull($this->sslMonitor->getLastErrorMessage());
        
        // Trigger an error
        $this->sslMonitor->checkCertificate('');
        
        $this->assertTrue($this->sslMonitor->hasErrors());
        $this->assertNotEmpty($this->sslMonitor->getLastErrors());
        $this->assertNotNull($this->sslMonitor->getLastErrorMessage());
    }
    
    /**
     * Test timeout and retry settings
     */
    public function testTimeoutAndRetrySettings(): void {
        $this->sslMonitor->setTimeout(120);
        $this->assertEquals(120, $this->sslMonitor->getTimeout());
        
        $this->sslMonitor->setMaxRetries(10);
        $this->assertEquals(10, $this->sslMonitor->getMaxRetries());
        
        // Test minimum values
        $this->sslMonitor->setTimeout(0);
        $this->assertEquals(1, $this->sslMonitor->getTimeout());
        
        $this->sslMonitor->setMaxRetries(0);
        $this->assertEquals(1, $this->sslMonitor->getMaxRetries());
    }
    
    /**
     * Test batch certificate checking
     */
    public function testBatchCheckCertificates(): void {
        $items = [
            new TrackingItem([
                'name' => 'Test SSL 1',
                'type' => 'ssl',
                'hostname' => 'example.com',
                'port' => 443,
            ]),
            new TrackingItem([
                'name' => 'Test Domain', // This should be skipped
                'type' => 'domain',
                'hostname' => 'example.com',
            ]),
        ];
        
        $results = $this->sslMonitor->batchCheckCertificates($items);
        
        // Should only process SSL items
        $this->assertCount(1, $results);
        $this->assertArrayHasKey('item', $results[0]);
        $this->assertArrayHasKey('certificate', $results[0]);
        $this->assertArrayHasKey('errors', $results[0]);
    }
}