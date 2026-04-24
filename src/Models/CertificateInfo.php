<?php
/**
 * SSL & Domain Expiry Tracker - CertificateInfo Model
 * 
 * Represents SSL certificate information extracted from certificate parsing.
 * Contains certificate details like issuer, subject, validity dates, and extensions.
 */

namespace App\Models;

use DateTime;
use Exception;

class CertificateInfo {
    public string $issuer;
    public string $subject;
    public DateTime $validFrom;
    public DateTime $validTo;
    public bool $isWildcard = false;
    public array $subjectAltNames = [];
    public ?string $serialNumber = null;
    public ?string $fingerprint = null;
    public ?string $signatureAlgorithm = null;
    public ?int $keySize = null;
    public ?string $keyType = null;
    public array $extensions = [];
    
    /**
     * Constructor
     * 
     * @param array $data Certificate data from OpenSSL parsing
     */
    public function __construct(array $data = []) {
        if (!empty($data)) {
            $this->fromArray($data);
        }
    }
    
    /**
     * Populate object from certificate data array
     * 
     * @param array $data Certificate data from openssl_x509_parse()
     * @return self
     */
    public function fromArray(array $data): self {
        // Basic certificate information
        $this->issuer = $this->formatDistinguishedName($data['issuer'] ?? []);
        $this->subject = $this->formatDistinguishedName($data['subject'] ?? []);
        
        // Validity dates
        $this->validFrom = $this->parseTimestamp($data['validFrom_time_t'] ?? null);
        $this->validTo = $this->parseTimestamp($data['validTo_time_t'] ?? null);
        
        // Certificate identifiers
        $this->serialNumber = $data['serialNumber'] ?? null;
        $this->signatureAlgorithm = $data['signatureTypeSN'] ?? null;
        
        // Extract Subject Alternative Names
        $this->extractSubjectAltNames($data);
        
        // Determine if wildcard certificate
        $this->determineWildcardStatus();
        
        // Extract key information
        $this->extractKeyInformation($data);
        
        // Store extensions
        $this->extensions = $data['extensions'] ?? [];
        
        return $this;
    }
    
    /**
     * Convert object to array
     * 
     * @return array
     */
    public function toArray(): array {
        return [
            'issuer' => $this->issuer,
            'subject' => $this->subject,
            'valid_from' => $this->validFrom->format('Y-m-d H:i:s'),
            'valid_to' => $this->validTo->format('Y-m-d H:i:s'),
            'is_wildcard' => $this->isWildcard,
            'subject_alt_names' => $this->subjectAltNames,
            'serial_number' => $this->serialNumber,
            'fingerprint' => $this->fingerprint,
            'signature_algorithm' => $this->signatureAlgorithm,
            'key_size' => $this->keySize,
            'key_type' => $this->keyType,
            'extensions' => $this->extensions,
        ];
    }
    
    /**
     * Format distinguished name from array to string
     * 
     * @param array $dn Distinguished name components
     * @return string Formatted DN string
     */
    private function formatDistinguishedName(array $dn): string {
        if (empty($dn)) {
            return '';
        }
        
        $parts = [];
        
        // Common DN components in order of preference
        $components = ['CN', 'OU', 'O', 'L', 'ST', 'C'];
        
        foreach ($components as $component) {
            if (isset($dn[$component])) {
                $value = is_array($dn[$component]) ? implode(', ', $dn[$component]) : $dn[$component];
                $parts[] = "{$component}={$value}";
            }
        }
        
        // Add any remaining components
        foreach ($dn as $key => $value) {
            if (!in_array($key, $components)) {
                $value = is_array($value) ? implode(', ', $value) : $value;
                $parts[] = "{$key}={$value}";
            }
        }
        
        return implode(', ', $parts);
    }
    
    /**
     * Parse timestamp to DateTime object
     * 
     * @param mixed $timestamp Unix timestamp or date string
     * @return DateTime
     */
    private function parseTimestamp($timestamp): DateTime {
        if ($timestamp === null) {
            return new DateTime();
        }
        
        if (is_numeric($timestamp)) {
            return new DateTime('@' . $timestamp);
        }
        
        try {
            return new DateTime($timestamp);
        } catch (Exception $e) {
            return new DateTime();
        }
    }
    
    /**
     * Extract Subject Alternative Names from certificate data
     * 
     * @param array $data Certificate data
     */
    private function extractSubjectAltNames(array $data): void {
        $this->subjectAltNames = [];
        
        // Check extensions for SAN
        if (isset($data['extensions']['subjectAltName'])) {
            $sanString = $data['extensions']['subjectAltName'];
            
            // Parse SAN string (format: "DNS:example.com, DNS:*.example.com, IP:192.168.1.1")
            $parts = explode(',', $sanString);
            
            foreach ($parts as $part) {
                $part = trim($part);
                if (preg_match('/^(DNS|IP|email):(.+)$/', $part, $matches)) {
                    $type = strtolower($matches[1]);
                    $value = trim($matches[2]);
                    
                    if (!isset($this->subjectAltNames[$type])) {
                        $this->subjectAltNames[$type] = [];
                    }
                    
                    $this->subjectAltNames[$type][] = $value;
                }
            }
        }
        
        // Also check subject CN if no SAN found
        if (empty($this->subjectAltNames) && isset($data['subject']['CN'])) {
            $cn = is_array($data['subject']['CN']) ? $data['subject']['CN'][0] : $data['subject']['CN'];
            $this->subjectAltNames['dns'] = [$cn];
        }
    }
    
    /**
     * Determine if this is a wildcard certificate
     */
    private function determineWildcardStatus(): void {
        $this->isWildcard = false;
        
        // Check subject CN
        if (preg_match('/^\*\./', $this->getCommonName())) {
            $this->isWildcard = true;
            return;
        }
        
        // Check SAN entries
        if (isset($this->subjectAltNames['dns'])) {
            foreach ($this->subjectAltNames['dns'] as $dns) {
                if (preg_match('/^\*\./', $dns)) {
                    $this->isWildcard = true;
                    return;
                }
            }
        }
    }
    
    /**
     * Extract key information from certificate data
     * 
     * @param array $data Certificate data
     */
    private function extractKeyInformation(array $data): void {
        // Try to extract key size and type from extensions or other fields
        if (isset($data['extensions']['keyUsage'])) {
            // This is a simplified extraction - in real implementation,
            // you might need to parse the actual public key
            $keyUsage = $data['extensions']['keyUsage'];
            
            // Common patterns for key types
            if (strpos($keyUsage, 'Digital Signature') !== false) {
                $this->keyType = 'RSA'; // Default assumption
            }
        }
        
        // Key size would typically require parsing the actual public key
        // This is a placeholder - real implementation would use openssl_pkey_get_details()
        $this->keySize = 2048; // Default assumption
    }
    
    /**
     * Get the Common Name from the certificate subject
     * 
     * @return string
     */
    public function getCommonName(): string {
        if (preg_match('/CN=([^,]+)/', $this->subject, $matches)) {
            return trim($matches[1]);
        }
        
        return '';
    }
    
    /**
     * Get the Organization from the certificate subject
     * 
     * @return string
     */
    public function getOrganization(): string {
        if (preg_match('/O=([^,]+)/', $this->subject, $matches)) {
            return trim($matches[1]);
        }
        
        return '';
    }
    
    /**
     * Get the issuer's Common Name
     * 
     * @return string
     */
    public function getIssuerName(): string {
        if (preg_match('/CN=([^,]+)/', $this->issuer, $matches)) {
            return trim($matches[1]);
        }
        
        return '';
    }
    
    /**
     * Check if certificate is currently valid
     * 
     * @return bool
     */
    public function isValid(): bool {
        $now = new DateTime();
        return $now >= $this->validFrom && $now <= $this->validTo;
    }
    
    /**
     * Check if certificate is expired
     * 
     * @return bool
     */
    public function isExpired(): bool {
        return new DateTime() > $this->validTo;
    }
    
    /**
     * Get days until expiry
     * 
     * @return int Number of days until expiry (negative if expired)
     */
    public function getDaysUntilExpiry(): int {
        $now = new DateTime();
        $interval = $now->diff($this->validTo);
        
        $days = $interval->days;
        if ($this->validTo < $now) {
            $days = -$days;
        }
        
        return $days;
    }
    
    /**
     * Get all domain names covered by this certificate
     * 
     * @return array Array of domain names
     */
    public function getCoveredDomains(): array {
        $domains = [];
        
        // Add CN if it's a domain name
        $cn = $this->getCommonName();
        if (!empty($cn) && !filter_var($cn, FILTER_VALIDATE_IP)) {
            $domains[] = $cn;
        }
        
        // Add SAN DNS entries
        if (isset($this->subjectAltNames['dns'])) {
            foreach ($this->subjectAltNames['dns'] as $dns) {
                if (!in_array($dns, $domains)) {
                    $domains[] = $dns;
                }
            }
        }
        
        return $domains;
    }
    
    /**
     * Check if certificate covers a specific domain
     * 
     * @param string $domain Domain to check
     * @return bool
     */
    public function coversDomain(string $domain): bool {
        $coveredDomains = $this->getCoveredDomains();
        
        foreach ($coveredDomains as $covered) {
            // Exact match
            if (strcasecmp($covered, $domain) === 0) {
                return true;
            }
            
            // Wildcard match
            if (strpos($covered, '*.') === 0) {
                $wildcardDomain = substr($covered, 2);
                if (strcasecmp($wildcardDomain, $domain) === 0 || 
                    (strpos($domain, '.') !== false && 
                     strcasecmp($wildcardDomain, substr($domain, strpos($domain, '.') + 1)) === 0)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get certificate validation status
     * 
     * @return array Status information
     */
    public function getValidationStatus(): array {
        $now = new DateTime();
        $status = 'valid';
        $message = 'Certificate is valid';
        
        if ($now < $this->validFrom) {
            $status = 'not_yet_valid';
            $message = 'Certificate is not yet valid';
        } elseif ($now > $this->validTo) {
            $status = 'expired';
            $message = 'Certificate has expired';
        } elseif ($this->getDaysUntilExpiry() <= SSL_EXPIRY_WARNING_DAYS) {
            $status = 'expiring_soon';
            $message = 'Certificate is expiring soon';
        }
        
        return [
            'status' => $status,
            'message' => $message,
            'days_until_expiry' => $this->getDaysUntilExpiry(),
            'valid_from' => $this->validFrom->format('Y-m-d H:i:s'),
            'valid_to' => $this->validTo->format('Y-m-d H:i:s'),
        ];
    }
    
    /**
     * Validate certificate data
     * 
     * @return array Array of validation errors
     */
    public function validate(): array {
        $errors = [];
        
        if (empty($this->subject)) {
            $errors[] = 'Certificate subject is required';
        }
        
        if (empty($this->issuer)) {
            $errors[] = 'Certificate issuer is required';
        }
        
        if ($this->validFrom >= $this->validTo) {
            $errors[] = 'Certificate valid from date must be before valid to date';
        }
        
        return $errors;
    }
}