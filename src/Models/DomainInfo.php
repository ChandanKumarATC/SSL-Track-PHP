<?php
/**
 * SSL & Domain Expiry Tracker - DomainInfo Model
 * 
 * Represents domain registration information extracted from WHOIS data.
 * Contains domain details like registrar, expiration date, and registration status.
 */

namespace App\Models;

use DateTime;
use Exception;

class DomainInfo {
    public string $domain;
    public ?string $registrar = null;
    public ?DateTime $expiryDate = null;
    public ?DateTime $registrationDate = null;
    public ?DateTime $lastUpdated = null;
    public string $status = 'active';
    public array $nameServers = [];
    public ?string $registrantOrg = null;
    public ?string $registrantCountry = null;
    public array $statusCodes = [];
    public ?string $whoisServer = null;
    public ?string $rawWhoisData = null;
    
    /**
     * Valid domain status values
     */
    const VALID_STATUSES = ['active', 'expired', 'pending', 'suspended', 'unknown'];
    
    /**
     * Constructor
     * 
     * @param array $data Domain data from WHOIS parsing
     */
    public function __construct(array $data = []) {
        if (!empty($data)) {
            $this->fromArray($data);
        }
    }
    
    /**
     * Populate object from WHOIS data array
     * 
     * @param array $data Domain data from WHOIS parsing
     * @return self
     */
    public function fromArray(array $data): self {
        $this->domain = $data['domain'] ?? '';
        $this->registrar = $data['registrar'] ?? null;
        $this->status = $data['status'] ?? 'active';
        $this->registrantOrg = $data['registrant_org'] ?? null;
        $this->registrantCountry = $data['registrant_country'] ?? null;
        $this->whoisServer = $data['whois_server'] ?? null;
        $this->rawWhoisData = $data['raw_whois_data'] ?? null;
        
        // Parse dates
        $this->expiryDate = $this->parseDateTime($data['expiry_date'] ?? null);
        $this->registrationDate = $this->parseDateTime($data['registration_date'] ?? null);
        $this->lastUpdated = $this->parseDateTime($data['last_updated'] ?? null);
        
        // Handle arrays
        $this->nameServers = $data['name_servers'] ?? [];
        $this->statusCodes = $data['status_codes'] ?? [];
        
        return $this;
    }
    
    /**
     * Convert object to array
     * 
     * @return array
     */
    public function toArray(): array {
        return [
            'domain' => $this->domain,
            'registrar' => $this->registrar,
            'expiry_date' => $this->expiryDate ? $this->expiryDate->format('Y-m-d H:i:s') : null,
            'registration_date' => $this->registrationDate ? $this->registrationDate->format('Y-m-d H:i:s') : null,
            'last_updated' => $this->lastUpdated ? $this->lastUpdated->format('Y-m-d H:i:s') : null,
            'status' => $this->status,
            'name_servers' => $this->nameServers,
            'registrant_org' => $this->registrantOrg,
            'registrant_country' => $this->registrantCountry,
            'status_codes' => $this->statusCodes,
            'whois_server' => $this->whoisServer,
            'raw_whois_data' => $this->rawWhoisData,
        ];
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
            // Handle various WHOIS date formats
            $formats = [
                'Y-m-d H:i:s',
                'Y-m-d\TH:i:s\Z',
                'Y-m-d\TH:i:s.u\Z',
                'Y-m-d',
                'd-M-Y',
                'd/m/Y',
                'm/d/Y',
                'Y.m.d',
                'd.m.Y',
                'Y-m-d H:i:s T',
                'D M d H:i:s Y',
            ];
            
            foreach ($formats as $format) {
                $date = DateTime::createFromFormat($format, $datetime);
                if ($date !== false) {
                    return $date;
                }
            }
            
            // Fallback to strtotime
            $timestamp = strtotime($datetime);
            if ($timestamp !== false) {
                return new DateTime('@' . $timestamp);
            }
            
        } catch (Exception $e) {
            // Log error but don't throw
            error_log("Failed to parse datetime: {$datetime} - " . $e->getMessage());
        }
        
        return null;
    }
    
    /**
     * Check if domain is expired
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
     * Check if domain is expiring soon
     * 
     * @return bool
     */
    public function isExpiringSoon(): bool {
        if ($this->expiryDate === null) {
            return false;
        }
        
        $now = new DateTime();
        $warningDate = (clone $now)->modify('+' . DOMAIN_EXPIRY_WARNING_DAYS . ' days');
        
        return $this->expiryDate <= $warningDate && $this->expiryDate > $now;
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
     * Get domain age in days
     * 
     * @return int|null Number of days since registration
     */
    public function getAgeInDays(): ?int {
        if ($this->registrationDate === null) {
            return null;
        }
        
        $now = new DateTime();
        $interval = $this->registrationDate->diff($now);
        
        return $interval->days;
    }
    
    /**
     * Check if domain data is stale and needs refresh
     * 
     * @param int $maxAgeHours Maximum age in hours before considering stale
     * @return bool
     */
    public function isStale(int $maxAgeHours = 24): bool {
        if ($this->lastUpdated === null) {
            return true;
        }
        
        $now = new DateTime();
        $maxAge = (clone $this->lastUpdated)->modify("+{$maxAgeHours} hours");
        
        return $now > $maxAge;
    }
    
    /**
     * Get domain validation status
     * 
     * @return array Status information
     */
    public function getValidationStatus(): array {
        $status = 'valid';
        $message = 'Domain is active';
        
        if ($this->isExpired()) {
            $status = 'expired';
            $message = 'Domain has expired';
        } elseif ($this->isExpiringSoon()) {
            $status = 'expiring_soon';
            $message = 'Domain is expiring soon';
        } elseif (in_array('PENDING DELETE', $this->statusCodes)) {
            $status = 'pending_delete';
            $message = 'Domain is pending deletion';
        } elseif (in_array('REDEMPTION PERIOD', $this->statusCodes)) {
            $status = 'redemption';
            $message = 'Domain is in redemption period';
        } elseif (in_array('CLIENT HOLD', $this->statusCodes) || in_array('SERVER HOLD', $this->statusCodes)) {
            $status = 'on_hold';
            $message = 'Domain is on hold';
        }
        
        return [
            'status' => $status,
            'message' => $message,
            'days_until_expiry' => $this->getDaysUntilExpiry(),
            'expiry_date' => $this->expiryDate ? $this->expiryDate->format('Y-m-d H:i:s') : null,
            'status_codes' => $this->statusCodes,
        ];
    }
    
    /**
     * Extract domain from URL or hostname
     * 
     * @param string $input URL, hostname, or domain
     * @return string Clean domain name
     */
    public static function extractDomain(string $input): string {
        // Remove protocol
        $domain = preg_replace('/^https?:\/\//', '', $input);
        
        // Remove www prefix
        $domain = preg_replace('/^www\./', '', $domain);
        
        // Remove port
        $domain = preg_replace('/:\d+$/', '', $domain);
        
        // Remove path
        $domain = preg_replace('/\/.*$/', '', $domain);
        
        // Convert to lowercase
        $domain = strtolower(trim($domain));
        
        return $domain;
    }
    
    /**
     * Get TLD (Top Level Domain) from domain name
     * 
     * @return string
     */
    public function getTLD(): string {
        $parts = explode('.', $this->domain);
        return end($parts);
    }
    
    /**
     * Get SLD (Second Level Domain) from domain name
     * 
     * @return string
     */
    public function getSLD(): string {
        $parts = explode('.', $this->domain);
        if (count($parts) >= 2) {
            return $parts[count($parts) - 2];
        }
        return '';
    }
    
    /**
     * Check if domain is an internationalized domain name (IDN)
     * 
     * @return bool
     */
    public function isIDN(): bool {
        return strpos($this->domain, 'xn--') !== false || 
               !mb_check_encoding($this->domain, 'ASCII');
    }
    
    /**
     * Validate domain information
     * 
     * @return array Array of validation errors
     */
    public function validate(): array {
        $errors = [];
        
        if (empty($this->domain)) {
            $errors[] = 'Domain name is required';
        } elseif (!$this->isValidDomainFormat($this->domain)) {
            $errors[] = 'Invalid domain name format';
        }
        
        if (!in_array($this->status, self::VALID_STATUSES)) {
            $errors[] = 'Invalid domain status';
        }
        
        if ($this->expiryDate && $this->registrationDate && 
            $this->expiryDate <= $this->registrationDate) {
            $errors[] = 'Expiry date must be after registration date';
        }
        
        return $errors;
    }
    
    /**
     * Validate domain name format
     * 
     * @param string $domain
     * @return bool
     */
    private function isValidDomainFormat(string $domain): bool {
        // Basic length check
        if (strlen($domain) > 253 || strlen($domain) < 1) {
            return false;
        }
        
        // Check for valid characters and structure
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $domain)) {
            return false;
        }
        
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
        
        return true;
    }
    
    /**
     * Parse common WHOIS status codes
     * 
     * @param string $statusString Raw status string from WHOIS
     * @return array Parsed status codes
     */
    public static function parseStatusCodes(string $statusString): array {
        $codes = [];
        
        // Common status patterns
        $patterns = [
            '/clientDeleteProhibited/i' => 'CLIENT DELETE PROHIBITED',
            '/clientTransferProhibited/i' => 'CLIENT TRANSFER PROHIBITED',
            '/clientUpdateProhibited/i' => 'CLIENT UPDATE PROHIBITED',
            '/clientRenewProhibited/i' => 'CLIENT RENEW PROHIBITED',
            '/clientHold/i' => 'CLIENT HOLD',
            '/serverDeleteProhibited/i' => 'SERVER DELETE PROHIBITED',
            '/serverTransferProhibited/i' => 'SERVER TRANSFER PROHIBITED',
            '/serverUpdateProhibited/i' => 'SERVER UPDATE PROHIBITED',
            '/serverRenewProhibited/i' => 'SERVER RENEW PROHIBITED',
            '/serverHold/i' => 'SERVER HOLD',
            '/pendingDelete/i' => 'PENDING DELETE',
            '/redemptionPeriod/i' => 'REDEMPTION PERIOD',
            '/ok/i' => 'OK',
            '/active/i' => 'ACTIVE',
        ];
        
        foreach ($patterns as $pattern => $code) {
            if (preg_match($pattern, $statusString)) {
                $codes[] = $code;
            }
        }
        
        return array_unique($codes);
    }
}