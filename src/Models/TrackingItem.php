<?php
/**
 * SSL & Domain Expiry Tracker - TrackingItem Model
 * 
 * Represents a domain or SSL certificate being monitored.
 * Handles data validation and database operations for tracking items.
 */

namespace App\Models;

use DateTime;
use Exception;
use InvalidArgumentException;

class TrackingItem {
    public ?int $id = null;
    public string $name;
    public string $type; // 'domain' or 'ssl'
    public string $hostname;
    public int $port = 443;
    public ?string $registrar = null;
    public ?array $adminEmails = null;
    public ?DateTime $expiryDate = null;
    public ?DateTime $lastChecked = null;
    public string $status = 'active';
    public ?string $errorMessage = null;
    public ?DateTime $createdAt = null;
    public ?DateTime $updatedAt = null;
    
    /**
     * Valid tracking item types
     */
    const VALID_TYPES = ['domain', 'ssl'];
    
    /**
     * Valid status values
     */
    const VALID_STATUSES = ['active', 'warning', 'expired', 'error'];
    
    /**
     * Constructor
     * 
     * @param array $data Initial data for the tracking item
     */
    public function __construct(array $data = []) {
        if (!empty($data)) {
            $this->fromArray($data);
        }
    }
    
    /**
     * Populate object from array data
     * 
     * @param array $data
     * @return self
     */
    public function fromArray(array $data): self {
        $this->id = isset($data['id']) ? (int)$data['id'] : null;
        $this->name = $data['name'] ?? '';
        $this->type = $data['type'] ?? '';
        $this->hostname = $data['hostname'] ?? '';
        $this->port = isset($data['port']) ? (int)$data['port'] : 443;
        $this->registrar = $data['registrar'] ?? null;
        $this->status = $data['status'] ?? 'active';
        $this->errorMessage = $data['error_message'] ?? null;
        
        // Handle admin emails (JSON string or array)
        if (isset($data['admin_emails'])) {
            if (is_string($data['admin_emails'])) {
                $this->adminEmails = json_decode($data['admin_emails'], true) ?: null;
            } elseif (is_array($data['admin_emails'])) {
                $this->adminEmails = $data['admin_emails'];
            }
        }
        
        // Handle datetime fields
        $this->expiryDate = $this->parseDateTime($data['expiry_date'] ?? null);
        $this->lastChecked = $this->parseDateTime($data['last_checked'] ?? null);
        $this->createdAt = $this->parseDateTime($data['created_at'] ?? null);
        $this->updatedAt = $this->parseDateTime($data['updated_at'] ?? null);
        
        return $this;
    }
    
    /**
     * Convert object to array for database operations
     * 
     * @return array
     */
    public function toArray(): array {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'type' => $this->type,
            'hostname' => $this->hostname,
            'port' => $this->port,
            'registrar' => $this->registrar,
            'admin_emails' => $this->adminEmails ? json_encode($this->adminEmails) : null,
            'expiry_date' => $this->expiryDate ? $this->expiryDate->format('Y-m-d H:i:s') : null,
            'last_checked' => $this->lastChecked ? $this->lastChecked->format('Y-m-d H:i:s') : null,
            'status' => $this->status,
            'error_message' => $this->errorMessage,
            'created_at' => $this->createdAt ? $this->createdAt->format('Y-m-d H:i:s') : null,
            'updated_at' => $this->updatedAt ? $this->updatedAt->format('Y-m-d H:i:s') : null,
        ];
    }
    
    /**
     * Validate the tracking item data
     * 
     * @return array Array of validation errors (empty if valid)
     */
    public function validate(): array {
        $errors = [];
        
        // Validate name
        if (empty($this->name)) {
            $errors[] = 'Name is required';
        } elseif (strlen($this->name) > 255) {
            $errors[] = 'Name must be 255 characters or less';
        }
        
        // Validate type
        if (empty($this->type)) {
            $errors[] = 'Type is required';
        } elseif (!in_array($this->type, self::VALID_TYPES)) {
            $errors[] = 'Type must be either "domain" or "ssl"';
        }
        
        // Validate hostname
        if (empty($this->hostname)) {
            $errors[] = 'Hostname is required';
        } else {
            $hostnameErrors = $this->validateHostname($this->hostname);
            $errors = array_merge($errors, $hostnameErrors);
        }
        
        // Validate port for SSL certificates
        if ($this->type === 'ssl') {
            if ($this->port < 1 || $this->port > 65535) {
                $errors[] = 'Port must be between 1 and 65535';
            }
        }
        
        // Validate status
        if (!in_array($this->status, self::VALID_STATUSES)) {
            $errors[] = 'Status must be one of: ' . implode(', ', self::VALID_STATUSES);
        }
        
        // Validate admin emails
        if ($this->adminEmails !== null) {
            $emailErrors = $this->validateAdminEmails($this->adminEmails);
            $errors = array_merge($errors, $emailErrors);
        }
        
        return $errors;
    }
    
    /**
     * Validate hostname/domain name
     * 
     * @param string $hostname
     * @return array Validation errors
     */
    private function validateHostname(string $hostname): array {
        $errors = [];
        
        // Basic length check
        if (strlen($hostname) > 255) {
            $errors[] = 'Hostname must be 255 characters or less';
            return $errors;
        }
        
        // Remove protocol if present
        $hostname = preg_replace('/^https?:\/\//', '', $hostname);
        
        // Remove port if present
        $hostname = preg_replace('/:\d+$/', '', $hostname);
        
        // Check for valid domain format
        if (!$this->isValidDomain($hostname)) {
            $errors[] = 'Invalid hostname or domain name format';
        }
        
        return $errors;
    }
    
    /**
     * Validate domain name format
     * 
     * @param string $domain
     * @return bool
     */
    private function isValidDomain(string $domain): bool {
        // Basic domain validation
        if (empty($domain) || strlen($domain) > 253) {
            return false;
        }
        
        // Check for valid characters and structure
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $domain)) {
            return false;
        }
        
        // Check that it's not just an IP address (for domain type)
        if ($this->type === 'domain' && filter_var($domain, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // Additional checks for domain names
        if ($this->type === 'domain') {
            // Must have at least one dot (TLD)
            if (strpos($domain, '.') === false) {
                return false;
            }
            
            // TLD must be at least 2 characters
            $parts = explode('.', $domain);
            $tld = end($parts);
            if (strlen($tld) < 2) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Validate admin email addresses
     * 
     * @param array $emails
     * @return array Validation errors
     */
    private function validateAdminEmails(array $emails): array {
        $errors = [];
        
        if (empty($emails)) {
            return $errors;
        }
        
        foreach ($emails as $email) {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Invalid email address: {$email}";
            }
        }
        
        return $errors;
    }
    
    /**
     * Parse datetime string to DateTime object
     * 
     * @param mixed $datetime
     * @return DateTime|null
     */
    private function parseDateTime($datetime): ?DateTime {
        if ($datetime === null || $datetime === '') {
            return null;
        }
        
        if ($datetime instanceof DateTime) {
            return $datetime;
        }
        
        try {
            return new DateTime($datetime);
        } catch (Exception $e) {
            return null;
        }
    }
    
    /**
     * Check if the item is expiring soon
     * 
     * @return bool
     */
    public function isExpiringSoon(): bool {
        if ($this->expiryDate === null) {
            return false;
        }
        
        $now = new DateTime();
        $threshold = $this->type === 'ssl' ? SSL_EXPIRY_WARNING_DAYS : DOMAIN_EXPIRY_WARNING_DAYS;
        $warningDate = (clone $now)->modify("+{$threshold} days");
        
        return $this->expiryDate <= $warningDate && $this->expiryDate > $now;
    }
    
    /**
     * Check if the item is expired
     * 
     * @return bool
     */
    public function isExpired(): bool {
        if ($this->expiryDate === null) {
            return false;
        }
        
        return $this->expiryDate <= new DateTime();
    }
    
    /**
     * Get days until expiry
     * 
     * @return int|null Number of days until expiry (negative if expired)
     */
    public function getDaysUntilExpiry(): ?int {
        if ($this->expiryDate === null) {
            return null;
        }
        
        $now = new DateTime();
        $interval = $now->diff($this->expiryDate);
        
        $days = $interval->days;
        if ($this->expiryDate < $now) {
            $days = -$days;
        }
        
        return $days;
    }
    
    /**
     * Get status color for display
     * 
     * @return string CSS color class
     */
    public function getStatusColor(): string {
        if ($this->isExpired()) {
            return 'red';
        } elseif ($this->isExpiringSoon()) {
            return 'yellow';
        } elseif ($this->status === 'error') {
            return 'red';
        } else {
            return 'green';
        }
    }
    
    /**
     * Sanitize input data to prevent injection attacks
     * 
     * @param array $data
     * @return array Sanitized data
     */
    public static function sanitizeInput(array $data): array {
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                // Remove null bytes and control characters
                $value = str_replace("\0", '', $value);
                $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
                
                // Trim whitespace
                $value = trim($value);
                
                // HTML encode for safety (will be decoded when needed)
                $sanitized[$key] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
            } elseif (is_array($value)) {
                $sanitized[$key] = self::sanitizeInput($value);
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }
}