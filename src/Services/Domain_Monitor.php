<?php
/**
 * SSL & Domain Expiry Tracker - Domain Monitor Service
 * 
 * Monitors domain expiration dates using WHOIS lookups.
 * Supports various registrar formats and internationalized domain names.
 */

namespace App\Services;

use App\Models\DomainInfo;
use App\Models\TrackingItem;
use DateTime;
use Exception;

class Domain_Monitor {
    private int $timeout;
    private int $maxRetries;
    private int $retryDelay;
    private array $lastErrors = [];
    
    /**
     * Common WHOIS servers for TLDs
     */
    private array $whoisServers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'info' => 'whois.afilias.net',
        'biz' => 'whois.neulevel.biz',
        'us' => 'whois.nic.us',
        'uk' => 'whois.nominet.uk',
        'co.uk' => 'whois.nominet.uk',
        'ca' => 'whois.cira.ca',
        'au' => 'whois.auda.org.au',
        'de' => 'whois.denic.de',
        'fr' => 'whois.afnic.fr',
        'it' => 'whois.nic.it',
        'nl' => 'whois.domain-registry.nl',
        'be' => 'whois.dns.be',
        'ch' => 'whois.nic.ch',
        'at' => 'whois.nic.at',
        'se' => 'whois.iis.se',
        'no' => 'whois.norid.no',
        'dk' => 'whois.dk-hostmaster.dk',
        'fi' => 'whois.fi',
        'pl' => 'whois.dns.pl',
        'cz' => 'whois.nic.cz',
        'sk' => 'whois.sk-nic.sk',
        'hu' => 'whois.nic.hu',
        'ro' => 'whois.rotld.ro',
        'bg' => 'whois.register.bg',
        'hr' => 'whois.dns.hr',
        'si' => 'whois.arnes.si',
        'lt' => 'whois.domreg.lt',
        'lv' => 'whois.nic.lv',
        'ee' => 'whois.tld.ee',
        'ru' => 'whois.tcinet.ru',
        'ua' => 'whois.ua',
        'by' => 'whois.cctld.by',
        'kz' => 'whois.nic.kz',
        'jp' => 'whois.jprs.jp',
        'kr' => 'whois.kr',
        'cn' => 'whois.cnnic.cn',
        'tw' => 'whois.twnic.net.tw',
        'hk' => 'whois.hkirc.hk',
        'sg' => 'whois.sgnic.sg',
        'my' => 'whois.mynic.my',
        'th' => 'whois.thnic.co.th',
        'in' => 'whois.registry.in',
        'pk' => 'whois.pknic.net.pk',
        'bd' => 'whois.btcl.net.bd',
        'lk' => 'whois.nic.lk',
        'nz' => 'whois.srs.net.nz',
        'br' => 'whois.registro.br',
        'ar' => 'whois.nic.ar',
        'cl' => 'whois.nic.cl',
        'co' => 'whois.nic.co',
        've' => 'whois.nic.ve',
        'mx' => 'whois.mx',
        'za' => 'whois.registry.net.za',
        'ke' => 'whois.kenic.or.ke',
        'ng' => 'whois.nic.net.ng',
        'eg' => 'whois.ripe.net',
        'ma' => 'whois.registre.ma',
        'tn' => 'whois.ati.tn',
        'il' => 'whois.isoc.org.il',
        'tr' => 'whois.nic.tr',
        'sa' => 'whois.nic.net.sa',
        'ae' => 'whois.aeda.net.ae',
        'ir' => 'whois.nic.ir',
    ];
    
    /**
     * Constructor
     * 
     * @param int $timeout Connection timeout in seconds
     * @param int $maxRetries Maximum retry attempts
     * @param int $retryDelay Delay between retries in seconds
     */
    public function __construct(
        int $timeout = WHOIS_TIMEOUT,
        int $maxRetries = MAX_RETRY_ATTEMPTS,
        int $retryDelay = RETRY_DELAY_SECONDS
    ) {
        $this->timeout = $timeout;
        $this->maxRetries = $maxRetries;
        $this->retryDelay = $retryDelay;
    }
    
    /**
     * Check domain expiration information
     * 
     * @param string $domain The domain name to check
     * @return DomainInfo|null Domain information or null on failure
     */
    public function checkDomain(string $domain): ?DomainInfo {
        $this->clearLastErrors();
        
        // Validate and normalize domain
        $domain = $this->normalizeDomain($domain);
        if (empty($domain)) {
            $this->addError('Invalid domain name provided');
            return null;
        }
        
        // Handle internationalized domain names
        $domain = $this->handleIDN($domain);
        
        // Attempt WHOIS lookup with retries
        for ($attempt = 1; $attempt <= $this->maxRetries; $attempt++) {
            try {
                $whoisData = $this->performWhoisLookup($domain);
                
                if (!empty($whoisData)) {
                    $domainInfo = $this->parseWhoisData($domain, $whoisData);
                    
                    if ($domainInfo !== null) {
                        return $domainInfo;
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
        
        $this->addError("Failed to retrieve WHOIS data after {$this->maxRetries} attempts");
        return null;
    }
    
    /**
     * Perform WHOIS lookup using socket connection
     * 
     * @param string $domain Domain name to lookup
     * @return string WHOIS response data
     * @throws Exception If WHOIS lookup fails
     */
    public function performWhoisLookup(string $domain): string {
        $tld = $this->extractTLD($domain);
        $whoisServer = $this->getWhoisServer($tld);
        
        if (empty($whoisServer)) {
            throw new Exception("No WHOIS server found for TLD: {$tld}");
        }
        
        // Create socket connection
        $socket = @fsockopen($whoisServer, 43, $errno, $errstr, $this->timeout);
        
        if (!$socket) {
            throw new Exception("Failed to connect to WHOIS server {$whoisServer}: {$errstr} (Error: {$errno})");
        }
        
        // Set socket timeout
        stream_set_timeout($socket, $this->timeout);
        
        // Send WHOIS query
        $query = $domain . "\r\n";
        fwrite($socket, $query);
        
        // Read response
        $response = '';
        while (!feof($socket)) {
            $line = fgets($socket, 4096);
            if ($line === false) {
                break;
            }
            $response .= $line;
        }
        
        fclose($socket);
        
        if (empty($response)) {
            throw new Exception("Empty response from WHOIS server {$whoisServer}");
        }
        
        // Handle redirects to other WHOIS servers
        $redirectServer = $this->extractRedirectServer($response);
        if ($redirectServer && $redirectServer !== $whoisServer) {
            return $this->performWhoisLookupOnServer($domain, $redirectServer);
        }
        
        return $response;
    }
    
    /**
     * Perform WHOIS lookup on specific server
     * 
     * @param string $domain Domain name
     * @param string $server WHOIS server
     * @return string WHOIS response
     * @throws Exception If lookup fails
     */
    private function performWhoisLookupOnServer(string $domain, string $server): string {
        $socket = @fsockopen($server, 43, $errno, $errstr, $this->timeout);
        
        if (!$socket) {
            throw new Exception("Failed to connect to WHOIS server {$server}: {$errstr} (Error: {$errno})");
        }
        
        stream_set_timeout($socket, $this->timeout);
        
        $query = $domain . "\r\n";
        fwrite($socket, $query);
        
        $response = '';
        while (!feof($socket)) {
            $line = fgets($socket, 4096);
            if ($line === false) {
                break;
            }
            $response .= $line;
        }
        
        fclose($socket);
        
        if (empty($response)) {
            throw new Exception("Empty response from WHOIS server {$server}");
        }
        
        return $response;
    }
    
    /**
     * Parse WHOIS response data for various registrar formats
     * 
     * @param string $domain Domain name
     * @param string $whoisData Raw WHOIS response
     * @return DomainInfo|null Parsed domain information
     */
    public function parseWhoisData(string $domain, string $whoisData): ?DomainInfo {
        $data = [
            'domain' => $domain,
            'raw_whois_data' => $whoisData,
            'last_updated' => new DateTime(),
        ];
        
        // Parse expiration date
        $expiryDate = $this->parseExpirationDate($whoisData);
        if ($expiryDate) {
            $data['expiry_date'] = $expiryDate;
        }
        
        // Parse registration date
        $registrationDate = $this->parseRegistrationDate($whoisData);
        if ($registrationDate) {
            $data['registration_date'] = $registrationDate;
        }
        
        // Parse registrar
        $registrar = $this->parseRegistrar($whoisData);
        if ($registrar) {
            $data['registrar'] = $registrar;
        }
        
        // Parse name servers
        $nameServers = $this->parseNameServers($whoisData);
        if (!empty($nameServers)) {
            $data['name_servers'] = $nameServers;
        }
        
        // Parse status codes
        $statusCodes = $this->parseStatusCodes($whoisData);
        if (!empty($statusCodes)) {
            $data['status_codes'] = $statusCodes;
        }
        
        // Parse registrant information
        $registrantOrg = $this->parseRegistrantOrg($whoisData);
        if ($registrantOrg) {
            $data['registrant_org'] = $registrantOrg;
        }
        
        $registrantCountry = $this->parseRegistrantCountry($whoisData);
        if ($registrantCountry) {
            $data['registrant_country'] = $registrantCountry;
        }
        
        // Determine WHOIS server used
        $whoisServer = $this->getWhoisServer($this->extractTLD($domain));
        if ($whoisServer) {
            $data['whois_server'] = $whoisServer;
        }
        
        // Determine domain status
        $data['status'] = $this->determineDomainStatus($data);
        
        return new DomainInfo($data);
    }
    
    /**
     * Parse expiration date from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return DateTime|null Expiration date
     */
    public function parseExpirationDate(string $whoisData): ?DateTime {
        $patterns = [
            // Common patterns for expiration date
            '/Registry Expiry Date:\s*(.+)/i',
            '/Registrar Registration Expiration Date:\s*(.+)/i',
            '/Expiration Date:\s*(.+)/i',
            '/Expires:\s*(.+)/i',
            '/Expiry Date:\s*(.+)/i',
            '/Domain Expiration Date:\s*(.+)/i',
            '/expire:\s*(.+)/i',
            '/Expiration Time:\s*(.+)/i',
            '/Registry Expiry:\s*(.+)/i',
            '/Expiry:\s*(.+)/i',
            '/Valid Until:\s*(.+)/i',
            '/Expires On:\s*(.+)/i',
            '/Record expires on\s*(.+)/i',
            '/Domain expires:\s*(.+)/i',
            '/Renewal date:\s*(.+)/i',
            '/paid-till:\s*(.+)/i',
            '/Expiry date:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whoisData, $matches)) {
                $dateString = trim($matches[1]);
                $date = $this->parseDateTime($dateString);
                if ($date) {
                    return $date;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Parse registration date from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return DateTime|null Registration date
     */
    private function parseRegistrationDate(string $whoisData): ?DateTime {
        $patterns = [
            '/Creation Date:\s*(.+)/i',
            '/Created:\s*(.+)/i',
            '/Domain Registration Date:\s*(.+)/i',
            '/Registration Date:\s*(.+)/i',
            '/Registered:\s*(.+)/i',
            '/created:\s*(.+)/i',
            '/Registration Time:\s*(.+)/i',
            '/Record created on\s*(.+)/i',
            '/Domain created:\s*(.+)/i',
            '/Created On:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whoisData, $matches)) {
                $dateString = trim($matches[1]);
                $date = $this->parseDateTime($dateString);
                if ($date) {
                    return $date;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Parse registrar from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return string|null Registrar name
     */
    private function parseRegistrar(string $whoisData): ?string {
        $patterns = [
            '/Registrar:\s*(.+)/i',
            '/Registrar Name:\s*(.+)/i',
            '/Sponsoring Registrar:\s*(.+)/i',
            '/Registrar Organization:\s*(.+)/i',
            '/Registrar Company:\s*(.+)/i',
            '/registrar:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whoisData, $matches)) {
                $registrar = trim($matches[1]);
                if (!empty($registrar) && $registrar !== 'Not Disclosed') {
                    return $registrar;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Parse name servers from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return array Name servers
     */
    private function parseNameServers(string $whoisData): array {
        $nameServers = [];
        
        $patterns = [
            '/Name Server:\s*(.+)/i',
            '/Nameserver:\s*(.+)/i',
            '/nserver:\s*(.+)/i',
            '/DNS:\s*(.+)/i',
            '/ns\d+:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern, $whoisData, $matches)) {
                foreach ($matches[1] as $ns) {
                    $ns = trim(strtolower($ns));
                    if (!empty($ns) && !in_array($ns, $nameServers)) {
                        $nameServers[] = $ns;
                    }
                }
            }
        }
        
        return $nameServers;
    }
    
    /**
     * Parse status codes from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return array Status codes
     */
    private function parseStatusCodes(string $whoisData): array {
        $statusCodes = [];
        
        $patterns = [
            '/Domain Status:\s*(.+)/i',
            '/Status:\s*(.+)/i',
            '/state:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern, $whoisData, $matches)) {
                foreach ($matches[1] as $status) {
                    $status = trim($status);
                    // Parse individual status codes
                    $codes = DomainInfo::parseStatusCodes($status);
                    $statusCodes = array_merge($statusCodes, $codes);
                }
            }
        }
        
        return array_unique($statusCodes);
    }
    
    /**
     * Parse registrant organization from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return string|null Registrant organization
     */
    private function parseRegistrantOrg(string $whoisData): ?string {
        $patterns = [
            '/Registrant Organization:\s*(.+)/i',
            '/Registrant:\s*(.+)/i',
            '/Organization:\s*(.+)/i',
            '/org:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whoisData, $matches)) {
                $org = trim($matches[1]);
                if (!empty($org) && $org !== 'Not Disclosed' && $org !== 'Private') {
                    return $org;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Parse registrant country from WHOIS data
     * 
     * @param string $whoisData WHOIS response
     * @return string|null Registrant country
     */
    private function parseRegistrantCountry(string $whoisData): ?string {
        $patterns = [
            '/Registrant Country:\s*(.+)/i',
            '/Country:\s*(.+)/i',
            '/country:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whoisData, $matches)) {
                $country = trim(strtoupper($matches[1]));
                if (!empty($country) && strlen($country) >= 2) {
                    return $country;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Parse datetime string to DateTime object
     * 
     * @param string $dateString Date string from WHOIS
     * @return DateTime|null Parsed date
     */
    private function parseDateTime(string $dateString): ?DateTime {
        if (empty($dateString)) {
            return null;
        }
        
        // Clean up the date string
        $dateString = trim($dateString);
        $dateString = preg_replace('/\s+/', ' ', $dateString);
        
        // Remove timezone abbreviations that might cause issues
        $dateString = preg_replace('/\s+(UTC|GMT|EST|PST|CST|MST)\s*$/', '', $dateString);
        
        // Common WHOIS date formats
        $formats = [
            'Y-m-d\TH:i:s\Z',
            'Y-m-d\TH:i:s.u\Z',
            'Y-m-d H:i:s',
            'Y-m-d',
            'd-M-Y',
            'd/m/Y',
            'm/d/Y',
            'Y.m.d',
            'd.m.Y',
            'Y-m-d H:i:s T',
            'D M d H:i:s Y',
            'M d Y',
            'd-M-Y H:i:s',
            'Y/m/d',
            'd M Y',
            'Y-m-d\TH:i:s',
            'c', // ISO 8601
        ];
        
        foreach ($formats as $format) {
            $date = DateTime::createFromFormat($format, $dateString);
            if ($date !== false) {
                return $date;
            }
        }
        
        // Fallback to strtotime
        try {
            $timestamp = strtotime($dateString);
            if ($timestamp !== false) {
                return new DateTime('@' . $timestamp);
            }
        } catch (Exception $e) {
            // Log error but continue
            error_log("Failed to parse date: {$dateString} - " . $e->getMessage());
        }
        
        return null;
    }
    
    /**
     * Normalize domain name
     * 
     * @param string $domain Raw domain input
     * @return string Normalized domain
     */
    private function normalizeDomain(string $domain): string {
        // Remove protocol
        $domain = preg_replace('/^https?:\/\//', '', $domain);
        
        // Remove www prefix
        $domain = preg_replace('/^www\./', '', $domain);
        
        // Remove port
        $domain = preg_replace('/:\d+$/', '', $domain);
        
        // Remove path
        $domain = preg_replace('/\/.*$/', '', $domain);
        
        // Convert to lowercase and trim
        $domain = strtolower(trim($domain));
        
        // Validate basic format
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $domain) || strpos($domain, '.') === false) {
            return '';
        }
        
        return $domain;
    }
    
    /**
     * Handle internationalized domain names (IDN)
     * 
     * @param string $domain Domain name
     * @return string ASCII-compatible encoding
     */
    private function handleIDN(string $domain): string {
        // Check if domain contains non-ASCII characters
        if (!mb_check_encoding($domain, 'ASCII')) {
            // Convert to ASCII-compatible encoding (Punycode)
            if (function_exists('idn_to_ascii')) {
                $asciiDomain = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
                if ($asciiDomain !== false) {
                    return $asciiDomain;
                }
            }
        }
        
        return $domain;
    }
    
    /**
     * Extract TLD from domain name
     * 
     * @param string $domain Domain name
     * @return string TLD
     */
    private function extractTLD(string $domain): string {
        $parts = explode('.', $domain);
        
        // Handle multi-part TLDs like co.uk, com.au
        if (count($parts) >= 3) {
            $lastTwo = $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
            if (isset($this->whoisServers[$lastTwo])) {
                return $lastTwo;
            }
        }
        
        return end($parts);
    }
    
    /**
     * Get WHOIS server for TLD
     * 
     * @param string $tld Top-level domain
     * @return string|null WHOIS server hostname
     */
    private function getWhoisServer(string $tld): ?string {
        return $this->whoisServers[$tld] ?? null;
    }
    
    /**
     * Extract redirect server from WHOIS response
     * 
     * @param string $response WHOIS response
     * @return string|null Redirect server
     */
    private function extractRedirectServer(string $response): ?string {
        $patterns = [
            '/Whois Server:\s*(.+)/i',
            '/Registrar WHOIS Server:\s*(.+)/i',
            '/refer:\s*(.+)/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response, $matches)) {
                $server = trim($matches[1]);
                if (!empty($server) && $server !== 'whois.verisign-grs.com') {
                    return $server;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Determine domain status based on parsed data
     * 
     * @param array $data Parsed domain data
     * @return string Domain status
     */
    private function determineDomainStatus(array $data): string {
        if (isset($data['expiry_date']) && $data['expiry_date'] instanceof DateTime) {
            $now = new DateTime();
            if ($data['expiry_date'] <= $now) {
                return 'expired';
            }
        }
        
        if (isset($data['status_codes']) && is_array($data['status_codes'])) {
            if (in_array('PENDING DELETE', $data['status_codes'])) {
                return 'pending';
            }
            if (in_array('CLIENT HOLD', $data['status_codes']) || 
                in_array('SERVER HOLD', $data['status_codes'])) {
                return 'suspended';
            }
        }
        
        return 'active';
    }
    
    /**
     * Update tracking item with domain information
     * 
     * @param TrackingItem $item Tracking item to update
     * @param DomainInfo|null $domainInfo Domain information
     * @return TrackingItem Updated tracking item
     */
    public function updateTrackingItem(TrackingItem $item, ?DomainInfo $domainInfo): TrackingItem {
        $item->lastChecked = new DateTime();
        
        if ($domainInfo !== null) {
            $item->expiryDate = $domainInfo->expiryDate;
            $item->registrar = $domainInfo->registrar;
            
            // Determine status based on domain validity
            if ($domainInfo->isExpired()) {
                $item->status = 'expired';
                $item->errorMessage = 'Domain has expired';
            } elseif ($domainInfo->isExpiringSoon()) {
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
     * Batch check multiple domains
     * 
     * @param array $trackingItems Array of TrackingItem objects
     * @return array Results array with domain info for each item
     */
    public function batchCheckDomains(array $trackingItems): array {
        $results = [];
        
        foreach ($trackingItems as $item) {
            if (!($item instanceof TrackingItem) || $item->type !== 'domain') {
                continue;
            }
            
            $domainInfo = $this->checkDomain($item->hostname);
            $updatedItem = $this->updateTrackingItem($item, $domainInfo);
            
            $results[] = [
                'item' => $updatedItem,
                'domain' => $domainInfo,
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
     * Add custom WHOIS server for TLD
     * 
     * @param string $tld Top-level domain
     * @param string $server WHOIS server hostname
     */
    public function addWhoisServer(string $tld, string $server): void {
        $this->whoisServers[strtolower($tld)] = $server;
    }
    
    /**
     * Get all configured WHOIS servers
     * 
     * @return array WHOIS servers mapping
     */
    public function getWhoisServers(): array {
        return $this->whoisServers;
    }
    
    /**
     * Log domain monitoring activity
     * 
     * @param string $domain Domain name
     * @param string $status Operation status
     * @param string|null $message Optional message
     */
    public function logActivity(string $domain, string $status, ?string $message = null): void {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'domain_monitor',
            'domain' => $domain,
            'status' => $status,
            'message' => $message,
        ];
        
        $logLine = json_encode($logEntry) . PHP_EOL;
        
        $logFile = LOG_DIR . '/domain_monitor.log';
        file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    }
}