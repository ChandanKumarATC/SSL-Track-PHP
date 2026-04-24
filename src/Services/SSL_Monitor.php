<?php
/**
 * SSL & Domain Expiry Tracker - SSL Monitor Service
 * 
 * Monitors SSL certificate expiration dates using PHP OpenSSL functions.
 * Retrieves certificates from endpoints and parses expiration data.
 */

namespace App\Services;

use App\Models\CertificateInfo;
use App\Models\TrackingItem;
use DateTime;
use Exception;

class SSL_Monitor {
    private int $timeout;
    private int $maxRetries;
    private int $retryDelay;
    private array $lastErrors = [];
    
    /**
     * Constructor
     * 
     * @param int $timeout Connection timeout in seconds
     * @param int $maxRetries Maximum retry attempts
     * @param int $retryDelay Delay between retries in seconds
     */
    public function __construct(
        int $timeout = SSL_TIMEOUT,
        int $maxRetries = MAX_RETRY_ATTEMPTS,
        int $retryDelay = RETRY_DELAY_SECONDS
    ) {
        $this->timeout = $timeout;
        $this->maxRetries = $maxRetries;
        $this->retryDelay = $retryDelay;
    }
    
    /**
     * Check SSL certificate for a given hostname and port
     * 
     * @param string $hostname The hostname to check
     * @param int $port The port to connect to (default 443)
     * @return CertificateInfo|null Certificate information or null on failure
     */
    public function checkCertificate(string $hostname, int $port = 443): ?CertificateInfo {
        $this->clearLastErrors();
        
        // Validate input
        if (empty($hostname)) {
            $this->addError('Hostname cannot be empty');
            return null;
        }
        
        if ($port < 1 || $port > 65535) {
            $this->addError('Port must be between 1 and 65535');
            return null;
        }
        
        // Attempt to retrieve certificate with retries
        for ($attempt = 1; $attempt <= $this->maxRetries; $attempt++) {
            try {
                $certificate = $this->retrieveCertificate($hostname, $port);
                
                if ($certificate !== null) {
                    $certificateData = $this->parseCertificateData($certificate);
                    
                    if ($certificateData !== null) {
                        return new CertificateInfo($certificateData);
                    }
                }
                
            } catch (Exception $e) {
                $this->addError("Attempt {$attempt}: " . $e->getMessage());
                
                // If this isn't the last attempt, wait before retrying
                if ($attempt < $this->maxRetries) {
                    sleep($this->retryDelay);
                }
            }
        }
        
        $this->addError("Failed to retrieve certificate after {$this->maxRetries} attempts");
        return null;
    }
    
    /**
     * Retrieve SSL certificate from hostname and port
     * 
     * @param string $hostname
     * @param int $port
     * @return resource|null Certificate resource or null on failure
     */
    private function retrieveCertificate(string $hostname, int $port): mixed {
        // Create SSL context
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'capture_peer_cert_chain' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'SNI_enabled' => true,
                'SNI_server_name' => $hostname,
            ],
            'socket' => [
                'timeout' => $this->timeout,
            ]
        ]);
        
        // Attempt to connect
        $address = "ssl://{$hostname}:{$port}";
        $socket = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            $this->timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );
        
        if ($socket === false) {
            throw new Exception("Failed to connect to {$hostname}:{$port} - {$errstr} (Error: {$errno})");
        }
        
        // Get the certificate from the context
        $params = stream_context_get_params($socket);
        $certificate = $params['options']['ssl']['peer_certificate'] ?? null;
        
        // Close the socket
        fclose($socket);
        
        if ($certificate === null) {
            throw new Exception("No certificate found in SSL handshake");
        }
        
        return $certificate;
    }
    
    /**
     * Parse certificate data using OpenSSL functions
     * 
     * @param resource $certificate Certificate resource
     * @return array|null Parsed certificate data or null on failure
     */
    private function parseCertificateData($certificate): ?array {
        if (!is_resource($certificate)) {
            $this->addError('Invalid certificate resource');
            return null;
        }
        
        // Parse the certificate
        $certData = openssl_x509_parse($certificate);
        
        if ($certData === false) {
            $this->addError('Failed to parse certificate data');
            return null;
        }
        
        // Get additional certificate details
        $certDetails = openssl_x509_get_details($certificate);
        
        if ($certDetails !== false) {
            // Merge additional details
            $certData = array_merge($certData, $certDetails);
        }
        
        // Get certificate fingerprint
        $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
        if ($fingerprint !== false) {
            $certData['fingerprint'] = $fingerprint;
        }
        
        // Get public key details
        $publicKey = openssl_pkey_get_public($certificate);
        if ($publicKey !== false) {
            $keyDetails = openssl_pkey_get_details($publicKey);
            if ($keyDetails !== false) {
                $certData['key_size'] = $keyDetails['bits'] ?? null;
                $certData['key_type'] = $this->getKeyType($keyDetails['type'] ?? null);
            }
            openssl_pkey_free($publicKey);
        }
        
        return $certData;
    }
    
    /**
     * Convert OpenSSL key type constant to string
     * 
     * @param int|null $keyType OpenSSL key type constant
     * @return string|null Key type string
     */
    private function getKeyType(?int $keyType): ?string {
        if ($keyType === null) {
            return null;
        }
        
        switch ($keyType) {
            case OPENSSL_KEYTYPE_RSA:
                return 'RSA';
            case OPENSSL_KEYTYPE_DSA:
                return 'DSA';
            case OPENSSL_KEYTYPE_DH:
                return 'DH';
            case OPENSSL_KEYTYPE_EC:
                return 'EC';
            default:
                return 'Unknown';
        }
    }
    
    /**
     * Calculate days until certificate expiry
     * 
     * @param int $expiryTimestamp Unix timestamp of expiry date
     * @return int Number of days until expiry (negative if expired)
     */
    public function calculateDaysUntilExpiry(int $expiryTimestamp): int {
        $now = new DateTime();
        $expiryDate = new DateTime('@' . $expiryTimestamp);
        
        $interval = $now->diff($expiryDate);
        $days = $interval->days;
        
        if ($expiryDate < $now) {
            $days = -$days;
        }
        
        return $days;
    }
    
    /**
     * Check if certificate is valid (not expired and currently valid)
     * 
     * @param array $certData Certificate data from openssl_x509_parse()
     * @return bool True if certificate is valid
     */
    public function isCertificateValid(array $certData): bool {
        $now = time();
        
        $validFrom = $certData['validFrom_time_t'] ?? 0;
        $validTo = $certData['validTo_time_t'] ?? 0;
        
        return $now >= $validFrom && $now <= $validTo;
    }
    
    /**
     * Check if certificate is expiring soon
     * 
     * @param array $certData Certificate data
     * @return bool True if certificate is expiring within warning threshold
     */
    public function isCertificateExpiringSoon(array $certData): bool {
        $validTo = $certData['validTo_time_t'] ?? 0;
        $daysUntilExpiry = $this->calculateDaysUntilExpiry($validTo);
        
        return $daysUntilExpiry <= SSL_EXPIRY_WARNING_DAYS && $daysUntilExpiry > 0;
    }
    
    /**
     * Get certificate status information
     * 
     * @param array $certData Certificate data
     * @return array Status information
     */
    public function getCertificateStatus(array $certData): array {
        $validTo = $certData['validTo_time_t'] ?? 0;
        $daysUntilExpiry = $this->calculateDaysUntilExpiry($validTo);
        
        if ($daysUntilExpiry < 0) {
            $status = 'expired';
            $message = 'Certificate has expired';
        } elseif ($daysUntilExpiry <= SSL_EXPIRY_WARNING_DAYS) {
            $status = 'expiring_soon';
            $message = 'Certificate is expiring soon';
        } else {
            $status = 'valid';
            $message = 'Certificate is valid';
        }
        
        return [
            'status' => $status,
            'message' => $message,
            'days_until_expiry' => $daysUntilExpiry,
            'expiry_date' => date('Y-m-d H:i:s', $validTo),
        ];
    }
    
    /**
     * Validate SSL endpoint connectivity
     * 
     * @param string $hostname
     * @param int $port
     * @return bool True if endpoint is reachable
     */
    public function validateEndpoint(string $hostname, int $port = 443): bool {
        try {
            $context = stream_context_create([
                'socket' => [
                    'timeout' => min($this->timeout, 10), // Use shorter timeout for validation
                ]
            ]);
            
            $socket = @stream_socket_client(
                "tcp://{$hostname}:{$port}",
                $errno,
                $errstr,
                min($this->timeout, 10),
                STREAM_CLIENT_CONNECT,
                $context
            );
            
            if ($socket !== false) {
                fclose($socket);
                return true;
            }
            
            return false;
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Update tracking item with certificate information
     * 
     * @param TrackingItem $item
     * @param CertificateInfo|null $certInfo
     * @return TrackingItem Updated tracking item
     */
    public function updateTrackingItem(TrackingItem $item, ?CertificateInfo $certInfo): TrackingItem {
        $item->lastChecked = new DateTime();
        
        if ($certInfo !== null) {
            $item->expiryDate = $certInfo->validTo;
            
            // Determine status based on certificate validity
            if ($certInfo->isExpired()) {
                $item->status = 'expired';
                $item->errorMessage = 'Certificate has expired';
            } elseif ($certInfo->getDaysUntilExpiry() <= SSL_EXPIRY_WARNING_DAYS) {
                $item->status = 'warning';
                $item->errorMessage = null;
            } else {
                $item->status = 'active';
                $item->errorMessage = null;
            }
        } else {
            $item->status = 'error';
            $item->errorMessage = $this->getLastErrorMessage();
        }
        
        return $item;
    }
    
    /**
     * Batch check multiple SSL certificates
     * 
     * @param array $trackingItems Array of TrackingItem objects
     * @return array Results array with certificate info for each item
     */
    public function batchCheckCertificates(array $trackingItems): array {
        $results = [];
        
        foreach ($trackingItems as $item) {
            if (!($item instanceof TrackingItem) || $item->type !== 'ssl') {
                continue;
            }
            
            $certInfo = $this->checkCertificate($item->hostname, $item->port);
            $updatedItem = $this->updateTrackingItem($item, $certInfo);
            
            $results[] = [
                'item' => $updatedItem,
                'certificate' => $certInfo,
                'errors' => $this->getLastErrors(),
            ];
            
            // Clear errors for next iteration
            $this->clearLastErrors();
        }
        
        return $results;
    }
    
    /**
     * Add error message to the error log
     * 
     * @param string $message Error message
     */
    private function addError(string $message): void {
        $this->lastErrors[] = [
            'timestamp' => date('Y-m-d H:i:s'),
            'message' => $message,
        ];
    }
    
    /**
     * Clear the error log
     */
    private function clearLastErrors(): void {
        $this->lastErrors = [];
    }
    
    /**
     * Get all error messages from the last operation
     * 
     * @return array Array of error messages
     */
    public function getLastErrors(): array {
        return $this->lastErrors;
    }
    
    /**
     * Get the last error message as a string
     * 
     * @return string|null Last error message or null if no errors
     */
    public function getLastErrorMessage(): ?string {
        if (empty($this->lastErrors)) {
            return null;
        }
        
        $lastError = end($this->lastErrors);
        return $lastError['message'] ?? null;
    }
    
    /**
     * Check if there were errors in the last operation
     * 
     * @return bool True if there were errors
     */
    public function hasErrors(): bool {
        return !empty($this->lastErrors);
    }
    
    /**
     * Get timeout setting
     * 
     * @return int Timeout in seconds
     */
    public function getTimeout(): int {
        return $this->timeout;
    }
    
    /**
     * Set timeout setting
     * 
     * @param int $timeout Timeout in seconds
     */
    public function setTimeout(int $timeout): void {
        $this->timeout = max(1, $timeout);
    }
    
    /**
     * Get max retry attempts
     * 
     * @return int Maximum retry attempts
     */
    public function getMaxRetries(): int {
        return $this->maxRetries;
    }
    
    /**
     * Set max retry attempts
     * 
     * @param int $maxRetries Maximum retry attempts
     */
    public function setMaxRetries(int $maxRetries): void {
        $this->maxRetries = max(1, $maxRetries);
    }
    
    /**
     * Log SSL monitoring activity
     * 
     * @param string $hostname
     * @param int $port
     * @param string $status
     * @param string|null $message
     */
    public function logActivity(string $hostname, int $port, string $status, ?string $message = null): void {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'ssl_monitor',
            'hostname' => $hostname,
            'port' => $port,
            'status' => $status,
            'message' => $message,
        ];
        
        $logLine = json_encode($logEntry) . PHP_EOL;
        
        $logFile = LOG_DIR . '/ssl_monitor.log';
        file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    }
}