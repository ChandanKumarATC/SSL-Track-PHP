<?php
/**
 * SSL & Domain Expiry Tracker - TrackingItem Unit Tests
 * 
 * Unit tests for the TrackingItem model class.
 */

use PHPUnit\Framework\TestCase;

// Include autoloader
require_once __DIR__ . '/../../src/autoload.php';

use App\Models\TrackingItem;

class TrackingItemTest extends TestCase {
    
    public function testTrackingItemCreation(): void {
        $data = [
            'name' => 'Test Domain',
            'type' => 'domain',
            'hostname' => 'example.com',
            'admin_emails' => ['admin@example.com'],
            'status' => 'active'
        ];
        
        $item = new TrackingItem($data);
        
        $this->assertEquals('Test Domain', $item->name);
        $this->assertEquals('domain', $item->type);
        $this->assertEquals('example.com', $item->hostname);
        $this->assertEquals(['admin@example.com'], $item->adminEmails);
        $this->assertEquals('active', $item->status);
    }
    
    public function testTrackingItemValidation(): void {
        $item = new TrackingItem();
        
        // Test empty item validation
        $errors = $item->validate();
        $this->assertNotEmpty($errors);
        $this->assertContains('Name is required', $errors);
        $this->assertContains('Type is required', $errors);
        $this->assertContains('Hostname is required', $errors);
    }
    
    public function testValidDomainValidation(): void {
        $item = new TrackingItem([
            'name' => 'Valid Domain',
            'type' => 'domain',
            'hostname' => 'valid-domain.com',
            'status' => 'active'
        ]);
        
        $errors = $item->validate();
        $this->assertEmpty($errors);
    }
    
    public function testInvalidDomainValidation(): void {
        $item = new TrackingItem([
            'name' => 'Invalid Domain',
            'type' => 'domain',
            'hostname' => 'invalid..domain',
            'status' => 'active'
        ]);
        
        $errors = $item->validate();
        $this->assertNotEmpty($errors);
    }
    
    public function testSSLValidation(): void {
        $item = new TrackingItem([
            'name' => 'SSL Certificate',
            'type' => 'ssl',
            'hostname' => 'ssl.example.com',
            'port' => 443,
            'status' => 'active'
        ]);
        
        $errors = $item->validate();
        $this->assertEmpty($errors);
    }
    
    public function testInvalidPortValidation(): void {
        $item = new TrackingItem([
            'name' => 'SSL Certificate',
            'type' => 'ssl',
            'hostname' => 'ssl.example.com',
            'port' => 70000, // Invalid port
            'status' => 'active'
        ]);
        
        $errors = $item->validate();
        $this->assertNotEmpty($errors);
        $this->assertContains('Port must be between 1 and 65535', $errors);
    }
    
    public function testEmailValidation(): void {
        $item = new TrackingItem([
            'name' => 'Test Item',
            'type' => 'domain',
            'hostname' => 'example.com',
            'admin_emails' => ['valid@example.com', 'invalid-email'],
            'status' => 'active'
        ]);
        
        $errors = $item->validate();
        $this->assertNotEmpty($errors);
    }
    
    public function testExpiryDateHandling(): void {
        $expiryDate = new DateTime('2024-12-31 23:59:59');
        
        $item = new TrackingItem([
            'name' => 'Test Item',
            'type' => 'domain',
            'hostname' => 'example.com',
            'expiry_date' => $expiryDate->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertInstanceOf(DateTime::class, $item->expiryDate);
        $this->assertEquals('2024-12-31 23:59:59', $item->expiryDate->format('Y-m-d H:i:s'));
    }
    
    public function testIsExpiringSoon(): void {
        // Create item expiring in 5 days (within SSL warning threshold)
        $expiryDate = (new DateTime())->modify('+5 days');
        
        $sslItem = new TrackingItem([
            'name' => 'SSL Certificate',
            'type' => 'ssl',
            'hostname' => 'ssl.example.com',
            'expiry_date' => $expiryDate->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertTrue($sslItem->isExpiringSoon());
        
        // Domain with same expiry should not be expiring soon (30-day threshold)
        $domainItem = new TrackingItem([
            'name' => 'Domain',
            'type' => 'domain',
            'hostname' => 'example.com',
            'expiry_date' => $expiryDate->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertFalse($domainItem->isExpiringSoon());
    }
    
    public function testIsExpired(): void {
        // Create expired item
        $expiryDate = (new DateTime())->modify('-1 day');
        
        $item = new TrackingItem([
            'name' => 'Expired Item',
            'type' => 'domain',
            'hostname' => 'expired.com',
            'expiry_date' => $expiryDate->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertTrue($item->isExpired());
    }
    
    public function testGetDaysUntilExpiry(): void {
        // Create item expiring in 10 days
        $expiryDate = (new DateTime())->modify('+10 days');
        
        $item = new TrackingItem([
            'name' => 'Test Item',
            'type' => 'domain',
            'hostname' => 'example.com',
            'expiry_date' => $expiryDate->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $days = $item->getDaysUntilExpiry();
        $this->assertEquals(10, $days);
    }
    
    public function testGetStatusColor(): void {
        // Test expired item
        $expiredItem = new TrackingItem([
            'name' => 'Expired',
            'type' => 'domain',
            'hostname' => 'expired.com',
            'expiry_date' => (new DateTime())->modify('-1 day')->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertEquals('red', $expiredItem->getStatusColor());
        
        // Test expiring soon item
        $expiringSoonItem = new TrackingItem([
            'name' => 'Expiring Soon',
            'type' => 'ssl',
            'hostname' => 'ssl.example.com',
            'expiry_date' => (new DateTime())->modify('+5 days')->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertEquals('yellow', $expiringSoonItem->getStatusColor());
        
        // Test active item
        $activeItem = new TrackingItem([
            'name' => 'Active',
            'type' => 'domain',
            'hostname' => 'active.com',
            'expiry_date' => (new DateTime())->modify('+60 days')->format('Y-m-d H:i:s'),
            'status' => 'active'
        ]);
        
        $this->assertEquals('green', $activeItem->getStatusColor());
    }
    
    public function testSanitizeInput(): void {
        $dirtyData = [
            'name' => "Test\0Name\x01",
            'hostname' => "  example.com  ",
            'admin_emails' => ['test@example.com', '  admin@test.com  ']
        ];
        
        $sanitized = TrackingItem::sanitizeInput($dirtyData);
        
        $this->assertEquals('TestName', $sanitized['name']);
        $this->assertEquals('example.com', $sanitized['hostname']);
        $this->assertIsArray($sanitized['admin_emails']);
    }
    
    public function testToArray(): void {
        $item = new TrackingItem([
            'id' => 1,
            'name' => 'Test Item',
            'type' => 'domain',
            'hostname' => 'example.com',
            'status' => 'active'
        ]);
        
        $array = $item->toArray();
        
        $this->assertIsArray($array);
        $this->assertEquals(1, $array['id']);
        $this->assertEquals('Test Item', $array['name']);
        $this->assertEquals('domain', $array['type']);
        $this->assertEquals('example.com', $array['hostname']);
        $this->assertEquals('active', $array['status']);
    }
}