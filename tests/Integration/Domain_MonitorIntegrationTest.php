<?php
/**
 * SSL & Domain Expiry Tracker - Domain_Monitor Integration Tests
 * 
 * Integration tests for Domain_Monitor with actual WHOIS lookups.
 * These tests require network connectivity and may be slower.
 */

use PHPUnit\Framework\TestCase;
use App\Services\Domain_Monitor;
use App\Models\DomainInfo;
use App\Models\TrackingItem;
use DateTime;

class Domain_MonitorIntegrationTest extends TestCase {
    private Domain_Monitor $domainMonitor;
    
    protected function setUp(): void {
        $this->domainMonitor = new Domain_Monitor(30, 2, 1);
    }
    
    /**
     * Test actual WHOIS lookup for a well-known domain
     * 
     * @group integration
     * @group network
     */
    public function testActualWhoisLookup(): void {
        // Use example.com as it's a reserved domain with stable WHOIS data
        $domainInfo = $this->domainMonitor->checkDomain('example.com');
        
        if ($domainInfo === null) {
            $this->markTestSkipped('WHOIS lookup failed - network connectivity issue or server unavailable');
        }
        
        $this->assertInstanceOf(DomainInfo::class, $domainInfo);
        $this->assertEquals('example.com', $domainInfo->domain);
        $this->assertNotNull($domainInfo->expiryDate);
        $this->assertInstanceOf(DateTime::class, $domainInfo->expiryDate);
        $this->assertNotEmpty($domainInfo->rawWhoisData);
        
        // example.com should have IANA as registrar
        $this->assertStringContains('IANA', $domainInfo->registrar ?? '');
    }
    
    /**
     * Test WHOIS lookup for different TLDs
     * 
     * @group integration
     * @group network
     * @dataProvider domainProvider
     */
    public function testDifferentTLDs(string $domain, string $expectedTLD): void {
        $domainInfo = $this->domainMonitor->checkDomain($domain);
        
        if ($domainInfo === null) {
            $this->markTestSkipped("WHOIS lookup failed for {$domain} - network connectivity issue or server unavailable");
        }
        
        $this->assertInstanceOf(DomainInfo::class, $domainInfo);
        $this->assertEquals($domain, $domainInfo->domain);
        $this->assertEquals($expectedTLD, $domainInfo->getTLD());
        
        // Should have some basic WHOIS data
        $this->assertNotEmpty($domainInfo->rawWhoisData);
    }
    
    /**
     * Data provider for different domain TLDs
     */
    public function domainProvider(): array {
        return [
            ['example.com', 'com'],
            ['example.org', 'org'],
            ['example.net', 'net'],
        ];
    }
    
    /**
     * Test WHOIS lookup with invalid domain
     * 
     * @group integration
     */
    public function testInvalidDomainLookup(): void {
        $domainInfo = $this->domainMonitor->checkDomain('this-domain-should-not-exist-12345.com');
        
        // Should return null for non-existent domains
        $this->assertNull($domainInfo);
        $this->assertTrue($this->domainMonitor->hasErrors());
        $this->assertNotEmpty($this->domainMonitor->getLastErrors());
    }
    
    /**
     * Test WHOIS lookup with unsupported TLD
     * 
     * @group integration
     */
    public function testUnsupportedTLD(): void {
        $domainInfo = $this->domainMonitor->checkDomain('example.unsupportedtld');
        
        // Should return null for unsupported TLDs
        $this->assertNull($domainInfo);
        $this->assertTrue($this->domainMonitor->hasErrors());
        
        $errorMessage = $this->domainMonitor->getLastErrorMessage();
        $this->assertStringContains('No WHOIS server found', $errorMessage);
    }
    
    /**
     * Test tracking item integration
     * 
     * @group integration
     * @group network
     */
    public function testTrackingItemIntegration(): void {
        $item = new TrackingItem([
            'name' => 'Example Domain',
            'type' => 'domain',
            'hostname' => 'example.com',
            'status' => 'active'
        ]);
        
        $domainInfo = $this->domainMonitor->checkDomain($item->hostname);
        
        if ($domainInfo === null) {
            $this->markTestSkipped('WHOIS lookup failed - network connectivity issue');
        }
        
        $updatedItem = $this->domainMonitor->updateTrackingItem($item, $domainInfo);
        
        $this->assertInstanceOf(DateTime::class, $updatedItem->lastChecked);
        $this->assertInstanceOf(DateTime::class, $updatedItem->expiryDate);
        $this->assertNotNull($updatedItem->registrar);
        $this->assertContains($updatedItem->status, ['active', 'warning', 'expired']);
    }
    
    /**
     * Test batch domain checking
     * 
     * @group integration
     * @group network
     */
    public function testBatchDomainChecking(): void {
        $items = [
            new TrackingItem([
                'name' => 'Example COM',
                'type' => 'domain',
                'hostname' => 'example.com'
            ]),
            new TrackingItem([
                'name' => 'Example ORG',
                'type' => 'domain',
                'hostname' => 'example.org'
            ]),
            new TrackingItem([
                'name' => 'SSL Certificate',
                'type' => 'ssl',
                'hostname' => 'example.com'
            ])
        ];
        
        $results = $this->domainMonitor->batchCheckDomains($items);
        
        // Should process only domain items (2 out of 3)
        $this->assertCount(2, $results);
        
        foreach ($results as $result) {
            $this->assertArrayHasKey('item', $result);
            $this->assertArrayHasKey('domain', $result);
            $this->assertArrayHasKey('errors', $result);
            
            $item = $result['item'];
            $this->assertInstanceOf(TrackingItem::class, $item);
            $this->assertEquals('domain', $item->type);
            $this->assertInstanceOf(DateTime::class, $item->lastChecked);
            
            // Check if domain lookup was successful
            if ($result['domain'] !== null) {
                $this->assertInstanceOf(DomainInfo::class, $result['domain']);
                $this->assertContains($item->status, ['active', 'warning', 'expired']);
            } else {
                $this->assertEquals('error', $item->status);
                $this->assertNotEmpty($result['errors']);
            }
        }
    }
    
    /**
     * Test WHOIS server connectivity
     * 
     * @group integration
     * @group network
     */
    public function testWhoisServerConnectivity(): void {
        $servers = $this->domainMonitor->getWhoisServers();
        
        // Test a few common WHOIS servers
        $testServers = [
            'com' => 'whois.verisign-grs.com',
            'org' => 'whois.pir.org',
            'net' => 'whois.verisign-grs.com'
        ];
        
        foreach ($testServers as $tld => $server) {
            $this->assertEquals($server, $servers[$tld], "WHOIS server for .{$tld} should be {$server}");
            
            // Test basic connectivity (port 43)
            $socket = @fsockopen($server, 43, $errno, $errstr, 10);
            if ($socket) {
                fclose($socket);
                $this->assertTrue(true, "Successfully connected to {$server}");
            } else {
                $this->markTestSkipped("Cannot connect to WHOIS server {$server}: {$errstr}");
            }
        }
    }
    
    /**
     * Test timeout handling
     * 
     * @group integration
     */
    public function testTimeoutHandling(): void {
        // Create monitor with very short timeout
        $shortTimeoutMonitor = new Domain_Monitor(1, 1, 0);
        
        // Try to lookup a domain that might timeout
        $domainInfo = $shortTimeoutMonitor->checkDomain('example.com');
        
        // Should either succeed or fail with timeout error
        if ($domainInfo === null) {
            $this->assertTrue($shortTimeoutMonitor->hasErrors());
            $errorMessage = $shortTimeoutMonitor->getLastErrorMessage();
            $this->assertNotEmpty($errorMessage);
        } else {
            $this->assertInstanceOf(DomainInfo::class, $domainInfo);
        }
    }
    
    /**
     * Test error logging
     * 
     * @group integration
     */
    public function testErrorLogging(): void {
        $logFile = LOG_DIR . '/domain_monitor.log';
        
        // Clear log file
        if (file_exists($logFile)) {
            unlink($logFile);
        }
        
        // Perform a domain check that should log activity
        $this->domainMonitor->checkDomain('example.com');
        $this->domainMonitor->logActivity('example.com', 'test', 'Integration test');
        
        $this->assertFileExists($logFile);
        
        $logContent = file_get_contents($logFile);
        $this->assertStringContains('domain_monitor', $logContent);
        $this->assertStringContains('example.com', $logContent);
        $this->assertStringContains('test', $logContent);
        $this->assertStringContains('Integration test', $logContent);
        
        // Verify JSON format
        $lines = explode("\n", trim($logContent));
        foreach ($lines as $line) {
            if (!empty($line)) {
                $decoded = json_decode($line, true);
                $this->assertIsArray($decoded);
                $this->assertArrayHasKey('timestamp', $decoded);
                $this->assertArrayHasKey('type', $decoded);
                $this->assertEquals('domain_monitor', $decoded['type']);
            }
        }
    }
    
    /**
     * Test performance with multiple domains
     * 
     * @group integration
     * @group network
     * @group performance
     */
    public function testPerformanceWithMultipleDomains(): void {
        $domains = ['example.com', 'example.org', 'example.net'];
        $startTime = microtime(true);
        
        $results = [];
        foreach ($domains as $domain) {
            $results[$domain] = $this->domainMonitor->checkDomain($domain);
        }
        
        $endTime = microtime(true);
        $totalTime = $endTime - $startTime;
        
        // Should complete within reasonable time (30 seconds for 3 domains)
        $this->assertLessThan(30, $totalTime, 'Domain lookups took too long');
        
        // Check results
        foreach ($results as $domain => $result) {
            if ($result !== null) {
                $this->assertInstanceOf(DomainInfo::class, $result);
                $this->assertEquals($domain, $result->domain);
            }
        }
    }
}