<?php
/**
 * SSL & Domain Expiry Tracker - Domain_Monitor Unit Tests
 * 
 * Unit tests for the Domain_Monitor service class.
 * Tests WHOIS parsing, domain validation, and error handling.
 */

use PHPUnit\Framework\TestCase;
use App\Services\Domain_Monitor;
use App\Models\DomainInfo;
use App\Models\TrackingItem;
use DateTime;

class Domain_MonitorTest extends TestCase {
    private Domain_Monitor $domainMonitor;
    
    protected function setUp(): void {
        $this->domainMonitor = new Domain_Monitor(30, 3, 1);
    }
    
    /**
     * Test domain normalization
     */
    public function testDomainNormalization(): void {
        $reflection = new ReflectionClass($this->domainMonitor);
        $method = $reflection->getMethod('normalizeDomain');
        $method->setAccessible(true);
        
        // Test various domain formats
        $this->assertEquals('example.com', $method->invoke($this->domainMonitor, 'https://example.com'));
        $this->assertEquals('example.com', $method->invoke($this->domainMonitor, 'http://www.example.com'));
        $this->assertEquals('example.com', $method->invoke($this->domainMonitor, 'example.com:443'));
        $this->assertEquals('example.com', $method->invoke($this->domainMonitor, 'example.com/path'));
        $this->assertEquals('example.com', $method->invoke($this->domainMonitor, 'EXAMPLE.COM'));
        
        // Test invalid domains
        $this->assertEquals('', $method->invoke($this->domainMonitor, 'invalid'));
        $this->assertEquals('', $method->invoke($this->domainMonitor, ''));
        $this->assertEquals('', $method->invoke($this->domainMonitor, 'invalid@domain'));
    }
    
    /**
     * Test TLD extraction
     */
    public function testTLDExtraction(): void {
        $reflection = new ReflectionClass($this->domainMonitor);
        $method = $reflection->getMethod('extractTLD');
        $method->setAccessible(true);
        
        // Test single TLD
        $this->assertEquals('com', $method->invoke($this->domainMonitor, 'example.com'));
        $this->assertEquals('org', $method->invoke($this->domainMonitor, 'test.org'));
        
        // Test multi-part TLD
        $this->assertEquals('co.uk', $method->invoke($this->domainMonitor, 'example.co.uk'));
        $this->assertEquals('com.au', $method->invoke($this->domainMonitor, 'test.com.au'));
        
        // Test subdomain
        $this->assertEquals('com', $method->invoke($this->domainMonitor, 'sub.example.com'));
    }
    
    /**
     * Test WHOIS server lookup
     */
    public function testWhoisServerLookup(): void {
        $reflection = new ReflectionClass($this->domainMonitor);
        $method = $reflection->getMethod('getWhoisServer');
        $method->setAccessible(true);
        
        // Test known TLDs
        $this->assertEquals('whois.verisign-grs.com', $method->invoke($this->domainMonitor, 'com'));
        $this->assertEquals('whois.pir.org', $method->invoke($this->domainMonitor, 'org'));
        $this->assertEquals('whois.nominet.uk', $method->invoke($this->domainMonitor, 'co.uk'));
        
        // Test unknown TLD
        $this->assertNull($method->invoke($this->domainMonitor, 'unknown'));
    }
    
    /**
     * Test expiration date parsing
     */
    public function testExpirationDateParsing(): void {
        $whoisData1 = "Registry Expiry Date: 2024-12-31T23:59:59Z\nOther data...";
        $whoisData2 = "Expiration Date: 31-Dec-2024\nOther data...";
        $whoisData3 = "Expires: 2024/12/31\nOther data...";
        
        $date1 = $this->domainMonitor->parseExpirationDate($whoisData1);
        $date2 = $this->domainMonitor->parseExpirationDate($whoisData2);
        $date3 = $this->domainMonitor->parseExpirationDate($whoisData3);
        
        $this->assertInstanceOf(DateTime::class, $date1);
        $this->assertInstanceOf(DateTime::class, $date2);
        $this->assertInstanceOf(DateTime::class, $date3);
        
        $this->assertEquals('2024-12-31', $date1->format('Y-m-d'));
        $this->assertEquals('2024-12-31', $date2->format('Y-m-d'));
        $this->assertEquals('2024-12-31', $date3->format('Y-m-d'));
    }
    
    /**
     * Test WHOIS data parsing
     */
    public function testWhoisDataParsing(): void {
        $whoisData = "
Domain Name: EXAMPLE.COM
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://res-dom.iana.org
Updated Date: 2023-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar IANA ID: 376
Registrar Abuse Contact Email: abuse@iana.org
Registrar Abuse Contact Phone: +1.3103015200
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
DNSSEC DS Data: 31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE
DNSSEC DS Data: 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C
DNSSEC DS Data: 43547 8 1 B6225AB2CC613E0DCA7962BDC2342EA4F1B56083
DNSSEC DS Data: 43547 8 2 615A64233543F66F44D68933625B17497C89A70E858ED76A2145997EDF96A918
DNSSEC DS Data: 31406 8 1 189968811E6EBA862DD6C209F75623D8D9ED9142
DNSSEC DS Data: 31406 8 2 F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D8F6B916D
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
";
        
        $domainInfo = $this->domainMonitor->parseWhoisData('example.com', $whoisData);
        
        $this->assertInstanceOf(DomainInfo::class, $domainInfo);
        $this->assertEquals('example.com', $domainInfo->domain);
        $this->assertEquals('RESERVED-Internet Assigned Numbers Authority', $domainInfo->registrar);
        $this->assertInstanceOf(DateTime::class, $domainInfo->expiryDate);
        $this->assertInstanceOf(DateTime::class, $domainInfo->registrationDate);
        $this->assertEquals('2024-08-13', $domainInfo->expiryDate->format('Y-m-d'));
        $this->assertEquals('1995-08-14', $domainInfo->registrationDate->format('Y-m-d'));
        
        // Check name servers
        $this->assertContains('a.iana-servers.net', $domainInfo->nameServers);
        $this->assertContains('b.iana-servers.net', $domainInfo->nameServers);
        
        // Check status codes
        $this->assertContains('CLIENT DELETE PROHIBITED', $domainInfo->statusCodes);
        $this->assertContains('CLIENT TRANSFER PROHIBITED', $domainInfo->statusCodes);
        $this->assertContains('CLIENT UPDATE PROHIBITED', $domainInfo->statusCodes);
    }
    
    /**
     * Test internationalized domain name handling
     */
    public function testIDNHandling(): void {
        $reflection = new ReflectionClass($this->domainMonitor);
        $method = $reflection->getMethod('handleIDN');
        $method->setAccessible(true);
        
        // Test ASCII domain (should remain unchanged)
        $this->assertEquals('example.com', $method->invoke($this->domainMonitor, 'example.com'));
        
        // Test IDN domain (if idn_to_ascii is available)
        if (function_exists('idn_to_ascii')) {
            $result = $method->invoke($this->domainMonitor, 'тест.com');
            $this->assertStringStartsWith('xn--', $result);
        }
    }
    
    /**
     * Test tracking item update
     */
    public function testTrackingItemUpdate(): void {
        $item = new TrackingItem([
            'name' => 'Test Domain',
            'type' => 'domain',
            'hostname' => 'example.com',
            'status' => 'active'
        ]);
        
        // Test with valid domain info
        $domainInfo = new DomainInfo([
            'domain' => 'example.com',
            'expiry_date' => (new DateTime())->modify('+60 days'),
            'registrar' => 'Test Registrar'
        ]);
        
        $updatedItem = $this->domainMonitor->updateTrackingItem($item, $domainInfo);
        
        $this->assertEquals('active', $updatedItem->status);
        $this->assertEquals('Test Registrar', $updatedItem->registrar);
        $this->assertInstanceOf(DateTime::class, $updatedItem->lastChecked);
        $this->assertNull($updatedItem->errorMessage);
        
        // Test with expired domain
        $expiredDomainInfo = new DomainInfo([
            'domain' => 'example.com',
            'expiry_date' => (new DateTime())->modify('-1 day'),
        ]);
        
        $updatedItem = $this->domainMonitor->updateTrackingItem($item, $expiredDomainInfo);
        
        $this->assertEquals('expired', $updatedItem->status);
        $this->assertEquals('Domain has expired', $updatedItem->errorMessage);
        
        // Test with null domain info (error case)
        $updatedItem = $this->domainMonitor->updateTrackingItem($item, null);
        
        $this->assertEquals('error', $updatedItem->status);
        $this->assertNotNull($updatedItem->errorMessage);
    }
    
    /**
     * Test error handling
     */
    public function testErrorHandling(): void {
        // Test with invalid domain
        $result = $this->domainMonitor->checkDomain('');
        
        $this->assertNull($result);
        $this->assertTrue($this->domainMonitor->hasErrors());
        $this->assertNotEmpty($this->domainMonitor->getLastErrors());
        $this->assertStringContains('Invalid domain name', $this->domainMonitor->getLastErrorMessage());
    }
    
    /**
     * Test timeout and retry settings
     */
    public function testTimeoutAndRetrySettings(): void {
        $this->assertEquals(30, $this->domainMonitor->getTimeout());
        $this->assertEquals(3, $this->domainMonitor->getMaxRetries());
        
        $this->domainMonitor->setTimeout(60);
        $this->domainMonitor->setMaxRetries(5);
        
        $this->assertEquals(60, $this->domainMonitor->getTimeout());
        $this->assertEquals(5, $this->domainMonitor->getMaxRetries());
        
        // Test minimum values
        $this->domainMonitor->setTimeout(0);
        $this->domainMonitor->setMaxRetries(0);
        
        $this->assertEquals(1, $this->domainMonitor->getTimeout());
        $this->assertEquals(1, $this->domainMonitor->getMaxRetries());
    }
    
    /**
     * Test custom WHOIS server addition
     */
    public function testCustomWhoisServer(): void {
        $this->domainMonitor->addWhoisServer('test', 'whois.test.com');
        
        $servers = $this->domainMonitor->getWhoisServers();
        $this->assertEquals('whois.test.com', $servers['test']);
    }
    
    /**
     * Test batch domain checking
     */
    public function testBatchDomainChecking(): void {
        $items = [
            new TrackingItem([
                'name' => 'Domain 1',
                'type' => 'domain',
                'hostname' => 'example.com'
            ]),
            new TrackingItem([
                'name' => 'SSL Cert',
                'type' => 'ssl',
                'hostname' => 'example.com'
            ]),
            new TrackingItem([
                'name' => 'Domain 2',
                'type' => 'domain',
                'hostname' => 'test.org'
            ])
        ];
        
        // Mock the checkDomain method to avoid actual WHOIS calls
        $monitor = $this->createPartialMock(Domain_Monitor::class, ['checkDomain']);
        $monitor->method('checkDomain')->willReturn(null);
        
        $results = $monitor->batchCheckDomains($items);
        
        // Should only process domain items (2 out of 3)
        $this->assertCount(2, $results);
        
        foreach ($results as $result) {
            $this->assertArrayHasKey('item', $result);
            $this->assertArrayHasKey('domain', $result);
            $this->assertArrayHasKey('errors', $result);
            $this->assertInstanceOf(TrackingItem::class, $result['item']);
        }
    }
    
    /**
     * Test redirect server extraction
     */
    public function testRedirectServerExtraction(): void {
        $reflection = new ReflectionClass($this->domainMonitor);
        $method = $reflection->getMethod('extractRedirectServer');
        $method->setAccessible(true);
        
        $whoisData1 = "Whois Server: whois.registrar.com\nOther data...";
        $whoisData2 = "Registrar WHOIS Server: whois.example.com\nOther data...";
        $whoisData3 = "refer: whois.test.com\nOther data...";
        
        $this->assertEquals('whois.registrar.com', $method->invoke($this->domainMonitor, $whoisData1));
        $this->assertEquals('whois.example.com', $method->invoke($this->domainMonitor, $whoisData2));
        $this->assertEquals('whois.test.com', $method->invoke($this->domainMonitor, $whoisData3));
        
        // Test no redirect
        $this->assertNull($method->invoke($this->domainMonitor, 'No redirect info'));
    }
    
    /**
     * Test domain status determination
     */
    public function testDomainStatusDetermination(): void {
        $reflection = new ReflectionClass($this->domainMonitor);
        $method = $reflection->getMethod('determineDomainStatus');
        $method->setAccessible(true);
        
        // Test expired domain
        $expiredData = ['expiry_date' => (new DateTime())->modify('-1 day')];
        $this->assertEquals('expired', $method->invoke($this->domainMonitor, $expiredData));
        
        // Test pending delete
        $pendingData = ['status_codes' => ['PENDING DELETE']];
        $this->assertEquals('pending', $method->invoke($this->domainMonitor, $pendingData));
        
        // Test on hold
        $holdData = ['status_codes' => ['CLIENT HOLD']];
        $this->assertEquals('suspended', $method->invoke($this->domainMonitor, $holdData));
        
        // Test active domain
        $activeData = ['expiry_date' => (new DateTime())->modify('+30 days')];
        $this->assertEquals('active', $method->invoke($this->domainMonitor, $activeData));
    }
    
    /**
     * Test logging functionality
     */
    public function testLogging(): void {
        $logFile = LOG_DIR . '/domain_monitor.log';
        
        // Clear log file
        if (file_exists($logFile)) {
            unlink($logFile);
        }
        
        $this->domainMonitor->logActivity('example.com', 'success', 'Test message');
        
        $this->assertFileExists($logFile);
        
        $logContent = file_get_contents($logFile);
        $this->assertStringContains('domain_monitor', $logContent);
        $this->assertStringContains('example.com', $logContent);
        $this->assertStringContains('success', $logContent);
        $this->assertStringContains('Test message', $logContent);
    }
}