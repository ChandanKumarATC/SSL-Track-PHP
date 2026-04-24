<?php
/**
 * SSL & Domain Expiry Tracker - Input Validator
 * 
 * Provides comprehensive input validation and sanitization to prevent
 * SQL injection attacks and ensure data integrity.
 */

namespace App\Utils;

use DateTime;
use Exception;

class Validator {
    
    /**
     * Validate and sanitize domain name
     * 
     * @param string $domain
     * @return array ['valid' => bool, 'domain' => string, 'errors' => array]
     */
    public static function validateDomain(string $domain): array {
        $errors = [];
        $originalDomain = $domain;
        
        // Sanitize input
        $domain = self::sanitizeString($domain);
        
        // Remove protocol if present
        $domain = preg_replace('/^https?:\/\//', '', $domain);
        
        // Remove www prefix
        $domain = preg_replace('/^www\./', '', $domain);
        
        // Remove port if present
        $domain = preg_replace('/:\d+$/', '', $domain);
        
        // Remove path if present
        $domain = preg_replace('/\/.*$/', '', $domain);
        
        // Convert to lowercase
        $domain = strtolower(trim($domain));
        
        // Basic validation
        if (empty($domain)) {
            $errors[] = 'Domain name cannot be empty';
            return ['valid' => false, 'domain' => '', 'errors' => $errors];
        }
        
        // Length validation
        if (strlen($domain) > 253) {
            $errors[] = 'Domain name is too long (maximum 253 characters)';
        }
        
        if (strlen($domain) < 1) {
            $errors[] = 'Domain name is too short';
        }
        
        // Format validation
        if (!self::isValidDomainFormat($domain)) {
            $errors[] = 'Invalid domain name format';
        }
        
        // Must have at least one dot (TLD)
        if (strpos($domain, '.') === false) {
            $errors[] = 'Domain name must include a top-level domain (TLD)';
        }
        
        // TLD validation
        $parts = explode('.', $domain);
        $tld = end($parts);
        if (strlen($tld) < 2) {
            $errors[] = 'Top-level domain must be at least 2 characters';
        }
        
        // Check for IP address (not allowed for domain names)
        if (filter_var($domain, FILTER_VALIDATE_IP)) {
            $errors[] = 'IP addresses are not valid domain names';
        }
        
        // Check for reserved/special domains
        if (self::isReservedDomain($domain)) {
            $errors[] = 'Reserved or special-use domain names are not allowed';
        }
        
        return [
            'valid' => empty($errors),
            'domain' => $domain,
            'errors' => $errors,
            'original' => $originalDomain
        ];
    }
    
    /**
     * Validate SSL endpoint (hostname and port)
     * 
     * @param string $hostname
     * @param int $port
     * @return array ['valid' => bool, 'hostname' => string, 'port' => int, 'errors' => array]
     */
    public static function validateSSLEndpoint(string $hostname, int $port = 443): array {
        $errors = [];
        $originalHostname = $hostname;
        
        // Sanitize hostname
        $hostname = self::sanitizeString($hostname);
        
        // Remove protocol if present
        $hostname = preg_replace('/^https?:\/\//', '', $hostname);
        
        // Extract port from hostname if present
        if (preg_match('/^(.+):(\d+)$/', $hostname, $matches)) {
            $hostname = $matches[1];
            $extractedPort = (int)$matches[2];
            if ($port === 443) { // Only use extracted port if default was provided
                $port = $extractedPort;
            }
        }
        
        // Remove path if present
        $hostname = preg_replace('/\/.*$/', '', $hostname);
        
        // Convert to lowercase
        $hostname = strtolower(trim($hostname));
        
        // Validate hostname
        if (empty($hostname)) {
            $errors[] = 'Hostname cannot be empty';
        } elseif (strlen($hostname) > 253) {
            $errors[] = 'Hostname is too long (maximum 253 characters)';
        } elseif (!self::isValidHostnameFormat($hostname)) {
            $errors[] = 'Invalid hostname format';
        }
        
        // Validate port
        if ($port < 1 || $port > 65535) {
            $errors[] = 'Port must be between 1 and 65535';
        }
        
        // Common SSL ports validation (warning, not error)
        $commonSSLPorts = [443, 8443, 993, 995, 465, 587, 636, 989, 990];
        if (!in_array($port, $commonSSLPorts)) {
            // This is just a warning, not an error
        }
        
        return [
            'valid' => empty($errors),
            'hostname' => $hostname,
            'port' => $port,
            'errors' => $errors,
            'original' => $originalHostname
        ];
    }
    
    /**
     * Validate email address
     * 
     * @param string $email
     * @return array ['valid' => bool, 'email' => string, 'errors' => array]
     */
    public static function validateEmail(string $email): array {
        $errors = [];
        $originalEmail = $email;
        
        // Sanitize email
        $email = self::sanitizeString($email);
        $email = trim($email);
        
        if (empty($email)) {
            $errors[] = 'Email address cannot be empty';
            return ['valid' => false, 'email' => '', 'errors' => $errors];
        }
        
        // Length validation
        if (strlen($email) > 254) {
            $errors[] = 'Email address is too long (maximum 254 characters)';
        }
        
        // Format validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email address format';
        }
        
        // Additional checks
        if (strpos($email, '..') !== false) {
            $errors[] = 'Email address cannot contain consecutive dots';
        }
        
        // Check for dangerous characters
        $dangerousChars = ['<', '>', '"', '\'', '&', '\0', '\n', '\r', '\t'];
        foreach ($dangerousChars as $char) {
            if (strpos($email, $char) !== false) {
                $errors[] = 'Email address contains invalid characters';
                break;
            }
        }
        
        return [
            'valid' => empty($errors),
            'email' => strtolower($email),
            'errors' => $errors,
            'original' => $originalEmail
        ];
    }
    
    /**
     * Validate array of email addresses
     * 
     * @param array $emails
     * @return array ['valid' => bool, 'emails' => array, 'errors' => array]
     */
    public static function validateEmails(array $emails): array {
        $validEmails = [];
        $allErrors = [];
        
        if (empty($emails)) {
            return ['valid' => true, 'emails' => [], 'errors' => []];
        }
        
        foreach ($emails as $index => $email) {
            $result = self::validateEmail($email);
            
            if ($result['valid']) {
                $validEmails[] = $result['email'];
            } else {
                $allErrors[] = "Email {$index}: " . implode(', ', $result['errors']);
            }
        }
        
        // Check for duplicates
        $uniqueEmails = array_unique($validEmails);
        if (count($uniqueEmails) !== count($validEmails)) {
            $allErrors[] = 'Duplicate email addresses found';
        }
        
        return [
            'valid' => empty($allErrors),
            'emails' => $uniqueEmails,
            'errors' => $allErrors
        ];
    }
    
    /**
     * Sanitize string input to prevent injection attacks
     * 
     * @param string $input
     * @return string Sanitized string
     */
    public static function sanitizeString(string $input): string {
        // Remove null bytes
        $input = str_replace("\0", '', $input);
        
        // Remove control characters except newline and tab
        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
        
        // Trim whitespace
        $input = trim($input);
        
        return $input;
    }
    
    /**
     * Sanitize array of data recursively
     * 
     * @param array $data
     * @return array Sanitized data
     */
    public static function sanitizeArray(array $data): array {
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            $key = self::sanitizeString($key);
            
            if (is_string($value)) {
                $sanitized[$key] = self::sanitizeString($value);
            } elseif (is_array($value)) {
                $sanitized[$key] = self::sanitizeArray($value);
            } elseif (is_numeric($value)) {
                $sanitized[$key] = $value;
            } elseif (is_bool($value)) {
                $sanitized[$key] = $value;
            } else {
                // Convert other types to string and sanitize
                $sanitized[$key] = self::sanitizeString((string)$value);
            }
        }
        
        return $sanitized;
    }
    
    /**
     * Validate integer within range
     * 
     * @param mixed $value
     * @param int $min
     * @param int $max
     * @return array ['valid' => bool, 'value' => int, 'errors' => array]
     */
    public static function validateInteger($value, int $min = PHP_INT_MIN, int $max = PHP_INT_MAX): array {
        $errors = [];
        
        if (!is_numeric($value)) {
            $errors[] = 'Value must be a number';
            return ['valid' => false, 'value' => 0, 'errors' => $errors];
        }
        
        $intValue = (int)$value;
        
        if ($intValue < $min) {
            $errors[] = "Value must be at least {$min}";
        }
        
        if ($intValue > $max) {
            $errors[] = "Value must be at most {$max}";
        }
        
        return [
            'valid' => empty($errors),
            'value' => $intValue,
            'errors' => $errors
        ];
    }
    
    /**
     * Validate date string
     * 
     * @param string $date
     * @param string $format Expected format (default: Y-m-d H:i:s)
     * @return array ['valid' => bool, 'date' => DateTime|null, 'errors' => array]
     */
    public static function validateDate(string $date, string $format = 'Y-m-d H:i:s'): array {
        $errors = [];
        
        if (empty($date)) {
            return ['valid' => true, 'date' => null, 'errors' => []];
        }
        
        try {
            $dateObj = DateTime::createFromFormat($format, $date);
            
            if ($dateObj === false) {
                $errors[] = "Invalid date format. Expected: {$format}";
                return ['valid' => false, 'date' => null, 'errors' => $errors];
            }
            
            // Check if the date string matches the parsed date (catches invalid dates like 2023-02-30)
            if ($dateObj->format($format) !== $date) {
                $errors[] = "Invalid date value";
                return ['valid' => false, 'date' => null, 'errors' => $errors];
            }
            
            return ['valid' => true, 'date' => $dateObj, 'errors' => []];
            
        } catch (Exception $e) {
            $errors[] = "Failed to parse date: " . $e->getMessage();
            return ['valid' => false, 'date' => null, 'errors' => $errors];
        }
    }
    
    /**
     * Check if domain format is valid
     * 
     * @param string $domain
     * @return bool
     */
    private static function isValidDomainFormat(string $domain): bool {
        // RFC 1035 compliant domain name validation
        return preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $domain) === 1;
    }
    
    /**
     * Check if hostname format is valid (allows IP addresses)
     * 
     * @param string $hostname
     * @return bool
     */
    private static function isValidHostnameFormat(string $hostname): bool {
        // Allow IP addresses for SSL endpoints
        if (filter_var($hostname, FILTER_VALIDATE_IP)) {
            return true;
        }
        
        // Allow domain names
        return self::isValidDomainFormat($hostname);
    }
    
    /**
     * Check if domain is reserved or special-use
     * 
     * @param string $domain
     * @return bool
     */
    private static function isReservedDomain(string $domain): bool {
        $reservedTLDs = [
            'localhost',
            'local',
            'test',
            'invalid',
            'example',
            'example.com',
            'example.net',
            'example.org',
        ];
        
        foreach ($reservedTLDs as $reserved) {
            if (strcasecmp($domain, $reserved) === 0 || 
                str_ends_with(strtolower($domain), '.' . strtolower($reserved))) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Validate tracking item type
     * 
     * @param string $type
     * @return array ['valid' => bool, 'type' => string, 'errors' => array]
     */
    public static function validateTrackingType(string $type): array {
        $errors = [];
        $type = strtolower(trim($type));
        
        $validTypes = ['domain', 'ssl'];
        
        if (empty($type)) {
            $errors[] = 'Tracking type is required';
        } elseif (!in_array($type, $validTypes)) {
            $errors[] = 'Tracking type must be either "domain" or "ssl"';
        }
        
        return [
            'valid' => empty($errors),
            'type' => $type,
            'errors' => $errors
        ];
    }
    
    /**
     * Validate tracking item status
     * 
     * @param string $status
     * @return array ['valid' => bool, 'status' => string, 'errors' => array]
     */
    public static function validateStatus(string $status): array {
        $errors = [];
        $status = strtolower(trim($status));
        
        $validStatuses = ['active', 'warning', 'expired', 'error'];
        
        if (empty($status)) {
            $status = 'active'; // Default status
        } elseif (!in_array($status, $validStatuses)) {
            $errors[] = 'Status must be one of: ' . implode(', ', $validStatuses);
        }
        
        return [
            'valid' => empty($errors),
            'status' => $status,
            'errors' => $errors
        ];
    }
    
    /**
     * Comprehensive validation for tracking item data
     * 
     * @param array $data Raw input data
     * @return array ['valid' => bool, 'data' => array, 'errors' => array]
     */
    public static function validateTrackingItemData(array $data): array {
        $sanitizedData = self::sanitizeArray($data);
        $validatedData = [];
        $allErrors = [];
        
        // Validate name
        $name = trim($sanitizedData['name'] ?? '');
        if (empty($name)) {
            $allErrors[] = 'Name is required';
        } elseif (strlen($name) > 255) {
            $allErrors[] = 'Name must be 255 characters or less';
        } else {
            $validatedData['name'] = $name;
        }
        
        // Validate type
        $typeResult = self::validateTrackingType($sanitizedData['type'] ?? '');
        if (!$typeResult['valid']) {
            $allErrors = array_merge($allErrors, $typeResult['errors']);
        } else {
            $validatedData['type'] = $typeResult['type'];
        }
        
        // Validate hostname/domain based on type
        if (isset($validatedData['type'])) {
            $hostname = $sanitizedData['hostname'] ?? '';
            
            if ($validatedData['type'] === 'domain') {
                $domainResult = self::validateDomain($hostname);
                if (!$domainResult['valid']) {
                    $allErrors = array_merge($allErrors, $domainResult['errors']);
                } else {
                    $validatedData['hostname'] = $domainResult['domain'];
                }
            } else { // SSL
                $port = (int)($sanitizedData['port'] ?? 443);
                $sslResult = self::validateSSLEndpoint($hostname, $port);
                if (!$sslResult['valid']) {
                    $allErrors = array_merge($allErrors, $sslResult['errors']);
                } else {
                    $validatedData['hostname'] = $sslResult['hostname'];
                    $validatedData['port'] = $sslResult['port'];
                }
            }
        }
        
        // Validate admin emails
        if (!empty($sanitizedData['admin_emails'])) {
            $emails = is_array($sanitizedData['admin_emails']) 
                ? $sanitizedData['admin_emails'] 
                : explode(',', $sanitizedData['admin_emails']);
            
            $emailResult = self::validateEmails($emails);
            if (!$emailResult['valid']) {
                $allErrors = array_merge($allErrors, $emailResult['errors']);
            } else {
                $validatedData['admin_emails'] = $emailResult['emails'];
            }
        }
        
        // Validate registrar (optional)
        if (!empty($sanitizedData['registrar'])) {
            $registrar = trim($sanitizedData['registrar']);
            if (strlen($registrar) > 255) {
                $allErrors[] = 'Registrar name must be 255 characters or less';
            } else {
                $validatedData['registrar'] = $registrar;
            }
        }
        
        // Validate status
        $statusResult = self::validateStatus($sanitizedData['status'] ?? 'active');
        if (!$statusResult['valid']) {
            $allErrors = array_merge($allErrors, $statusResult['errors']);
        } else {
            $validatedData['status'] = $statusResult['status'];
        }
        
        return [
            'valid' => empty($allErrors),
            'data' => $validatedData,
            'errors' => $allErrors
        ];
    }
}