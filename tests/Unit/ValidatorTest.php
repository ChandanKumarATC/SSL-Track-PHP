<?php
/**
 * SSL & Domain Expiry Tracker - Validator Unit Tests
 * 
 * Unit tests for the Validator utility class.
 */

use PHPUnit\Framework\TestCase;

// Include autoloader
require_once __DIR__ . '/../../src/autoload.php';

use App\Utils\Validator;

class ValidatorTest extends TestCase {
    
    public function testValidDomainValidation(): void {
        $result = Validator::validateDomain('example.com');
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('example.com', $result['domain']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testInvalidDomainValidation(): void {
        // Test empty domain
        $result = Validator::validateDomain('');
        $this->assertFalse($result['valid']);
        $this->assertContains('Domain name cannot be empty', $result['errors']);
        
        // Test domain without TLD
        $result = Validator::validateDomain('invalid');
        $this->assertFalse($result['valid']);
        $this->assertContains('Domain name must include a top-level domain (TLD)', $result['errors']);
        
        // Test IP address (not allowed for domains)
        $result = Validator::validateDomain('192.168.1.1');
        $this->assertFalse($result['valid']);
        $this->assertContains('IP addresses are not valid domain names', $result['errors']);
    }
    
    public function testDomainSanitization(): void {
        // Test protocol removal
        $result = Validator::validateDomain('https://example.com');
        $this->assertTrue($result['valid']);
        $this->assertEquals('example.com', $result['domain']);
        
        // Test www removal
        $result = Validator::validateDomain('www.example.com');
        $this->assertTrue($result['valid']);
        $this->assertEquals('example.com', $result['domain']);
        
        // Test port removal
        $result = Validator::validateDomain('example.com:8080');
        $this->assertTrue($result['valid']);
        $this->assertEquals('example.com', $result['domain']);
        
        // Test path removal
        $result = Validator::validateDomain('example.com/path/to/page');
        $this->assertTrue($result['valid']);
        $this->assertEquals('example.com', $result['domain']);
    }
    
    public function testSSLEndpointValidation(): void {
        $result = Validator::validateSSLEndpoint('ssl.example.com', 443);
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('ssl.example.com', $result['hostname']);
        $this->assertEquals(443, $result['port']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testSSLEndpointWithIP(): void {
        $result = Validator::validateSSLEndpoint('192.168.1.1', 443);
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('192.168.1.1', $result['hostname']);
        $this->assertEquals(443, $result['port']);
    }
    
    public function testInvalidSSLEndpoint(): void {
        // Test invalid port
        $result = Validator::validateSSLEndpoint('ssl.example.com', 70000);
        $this->assertFalse($result['valid']);
        $this->assertContains('Port must be between 1 and 65535', $result['errors']);
        
        // Test empty hostname
        $result = Validator::validateSSLEndpoint('', 443);
        $this->assertFalse($result['valid']);
        $this->assertContains('Hostname cannot be empty', $result['errors']);
    }
    
    public function testEmailValidation(): void {
        $result = Validator::validateEmail('test@example.com');
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('test@example.com', $result['email']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testInvalidEmailValidation(): void {
        // Test invalid email format
        $result = Validator::validateEmail('invalid-email');
        $this->assertFalse($result['valid']);
        $this->assertContains('Invalid email address format', $result['errors']);
        
        // Test empty email
        $result = Validator::validateEmail('');
        $this->assertFalse($result['valid']);
        $this->assertContains('Email address cannot be empty', $result['errors']);
        
        // Test email with dangerous characters
        $result = Validator::validateEmail('test<script>@example.com');
        $this->assertFalse($result['valid']);
        $this->assertContains('Email address contains invalid characters', $result['errors']);
    }
    
    public function testEmailArrayValidation(): void {
        $emails = ['test1@example.com', 'test2@example.com', 'valid@test.org'];
        $result = Validator::validateEmails($emails);
        
        $this->assertTrue($result['valid']);
        $this->assertCount(3, $result['emails']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testEmailArrayWithInvalid(): void {
        $emails = ['test1@example.com', 'invalid-email', 'test2@example.com'];
        $result = Validator::validateEmails($emails);
        
        $this->assertFalse($result['valid']);
        $this->assertCount(2, $result['emails']); // Only valid emails
        $this->assertNotEmpty($result['errors']);
    }
    
    public function testStringSanitization(): void {
        $input = "Test\0String\x01With\x02Control\x03Chars";
        $sanitized = Validator::sanitizeString($input);
        
        $this->assertEquals('TestStringWithControlChars', $sanitized);
    }
    
    public function testArraySanitization(): void {
        $input = [
            'name' => "Test\0Name",
            'email' => "  test@example.com  ",
            'nested' => [
                'value' => "Nested\x01Value"
            ]
        ];
        
        $sanitized = Validator::sanitizeArray($input);
        
        $this->assertEquals('TestName', $sanitized['name']);
        $this->assertEquals('test@example.com', $sanitized['email']);
        $this->assertEquals('NestedValue', $sanitized['nested']['value']);
    }
    
    public function testIntegerValidation(): void {
        $result = Validator::validateInteger('123', 1, 1000);
        
        $this->assertTrue($result['valid']);
        $this->assertEquals(123, $result['value']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testInvalidIntegerValidation(): void {
        // Test non-numeric value
        $result = Validator::validateInteger('abc');
        $this->assertFalse($result['valid']);
        $this->assertContains('Value must be a number', $result['errors']);
        
        // Test out of range
        $result = Validator::validateInteger('1000', 1, 100);
        $this->assertFalse($result['valid']);
        $this->assertContains('Value must be at most 100', $result['errors']);
    }
    
    public function testTrackingTypeValidation(): void {
        $result = Validator::validateTrackingType('domain');
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('domain', $result['type']);
        $this->assertEmpty($result['errors']);
        
        $result = Validator::validateTrackingType('ssl');
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('ssl', $result['type']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testInvalidTrackingType(): void {
        $result = Validator::validateTrackingType('invalid');
        
        $this->assertFalse($result['valid']);
        $this->assertContains('Tracking type must be either "domain" or "ssl"', $result['errors']);
    }
    
    public function testStatusValidation(): void {
        $result = Validator::validateStatus('active');
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('active', $result['status']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testDefaultStatus(): void {
        $result = Validator::validateStatus('');
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('active', $result['status']); // Default status
        $this->assertEmpty($result['errors']);
    }
    
    public function testTrackingItemDataValidation(): void {
        $data = [
            'name' => 'Test Domain',
            'type' => 'domain',
            'hostname' => 'example.com',
            'admin_emails' => ['admin@example.com'],
            'status' => 'active'
        ];
        
        $result = Validator::validateTrackingItemData($data);
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('Test Domain', $result['data']['name']);
        $this->assertEquals('domain', $result['data']['type']);
        $this->assertEquals('example.com', $result['data']['hostname']);
        $this->assertEquals(['admin@example.com'], $result['data']['admin_emails']);
        $this->assertEquals('active', $result['data']['status']);
        $this->assertEmpty($result['errors']);
    }
    
    public function testInvalidTrackingItemData(): void {
        $data = [
            'name' => '', // Empty name
            'type' => 'invalid', // Invalid type
            'hostname' => 'invalid..domain', // Invalid hostname
            'admin_emails' => ['invalid-email'], // Invalid email
        ];
        
        $result = Validator::validateTrackingItemData($data);
        
        $this->assertFalse($result['valid']);
        $this->assertNotEmpty($result['errors']);
        $this->assertContains('Name is required', $result['errors']);
    }
    
    public function testSSLTrackingItemValidation(): void {
        $data = [
            'name' => 'SSL Certificate',
            'type' => 'ssl',
            'hostname' => 'ssl.example.com',
            'port' => '443',
            'status' => 'active'
        ];
        
        $result = Validator::validateTrackingItemData($data);
        
        $this->assertTrue($result['valid']);
        $this->assertEquals('SSL Certificate', $result['data']['name']);
        $this->assertEquals('ssl', $result['data']['type']);
        $this->assertEquals('ssl.example.com', $result['data']['hostname']);
        $this->assertEquals(443, $result['data']['port']);
        $this->assertEmpty($result['errors']);
    }
}