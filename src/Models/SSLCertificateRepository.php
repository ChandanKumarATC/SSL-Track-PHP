<?php
/**
 * SSL & Domain Expiry Tracker - SSL Certificate Repository
 * 
 * Database access layer for SSL certificate data with CRUD operations.
 * Manages the ssl_certificates table and related operations.
 */

namespace App\Models;

use Database;
use Exception;
use PDOException;

class SSLCertificateRepository {
    private Database $db;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->db = Database::getInstance();
    }
    
    /**
     * Create SSL certificate record
     * 
     * @param int $trackingItemId
     * @param CertificateInfo $certInfo
     * @param array $additionalData Additional certificate data (paths, etc.)
     * @return int The ID of the created certificate record
     * @throws Exception if creation fails
     */
    public function create(int $trackingItemId, CertificateInfo $certInfo, array $additionalData = []): int {
        $sql = "INSERT INTO ssl_certificates (
            tracking_item_id, issuer, subject, is_wildcard,
            certificate_path, private_key_path, chain_path, auto_renew
        ) VALUES (
            :tracking_item_id, :issuer, :subject, :is_wildcard,
            :certificate_path, :private_key_path, :chain_path, :auto_renew
        )";
        
        $params = [
            ':tracking_item_id' => $trackingItemId,
            ':issuer' => $certInfo->getIssuerName(),
            ':subject' => $certInfo->getCommonName(),
            ':is_wildcard' => $certInfo->isWildcard,
            ':certificate_path' => $additionalData['certificate_path'] ?? null,
            ':private_key_path' => $additionalData['private_key_path'] ?? null,
            ':chain_path' => $additionalData['chain_path'] ?? null,
            ':auto_renew' => $additionalData['auto_renew'] ?? true,
        ];
        
        try {
            return (int)$this->db->insert($sql, $params);
        } catch (PDOException $e) {
            throw new Exception('Failed to create SSL certificate record: ' . $e->getMessage());
        }
    }
    
    /**
     * Find SSL certificate by tracking item ID
     * 
     * @param int $trackingItemId
     * @return array|null Certificate data
     */
    public function findByTrackingItemId(int $trackingItemId): ?array {
        $sql = "SELECT * FROM ssl_certificates WHERE tracking_item_id = :tracking_item_id";
        
        try {
            return $this->db->fetchOne($sql, [':tracking_item_id' => $trackingItemId]);
        } catch (PDOException $e) {
            error_log('Failed to find SSL certificate: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Update SSL certificate record
     * 
     * @param int $id Certificate ID
     * @param CertificateInfo $certInfo
     * @param array $additionalData
     * @return bool Success status
     * @throws Exception if update fails
     */
    public function update(int $id, CertificateInfo $certInfo, array $additionalData = []): bool {
        $sql = "UPDATE ssl_certificates SET 
            issuer = :issuer,
            subject = :subject,
            is_wildcard = :is_wildcard,
            certificate_path = :certificate_path,
            private_key_path = :private_key_path,
            chain_path = :chain_path,
            auto_renew = :auto_renew,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id";
        
        $params = [
            ':id' => $id,
            ':issuer' => $certInfo->getIssuerName(),
            ':subject' => $certInfo->getCommonName(),
            ':is_wildcard' => $certInfo->isWildcard,
            ':certificate_path' => $additionalData['certificate_path'] ?? null,
            ':private_key_path' => $additionalData['private_key_path'] ?? null,
            ':chain_path' => $additionalData['chain_path'] ?? null,
            ':auto_renew' => $additionalData['auto_renew'] ?? true,
        ];
        
        try {
            $affectedRows = $this->db->update($sql, $params);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            throw new Exception('Failed to update SSL certificate: ' . $e->getMessage());
        }
    }
    
    /**
     * Delete SSL certificate record
     * 
     * @param int $id
     * @return bool Success status
     * @throws Exception if deletion fails
     */
    public function delete(int $id): bool {
        $sql = "DELETE FROM ssl_certificates WHERE id = :id";
        
        try {
            $affectedRows = $this->db->delete($sql, [':id' => $id]);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            throw new Exception('Failed to delete SSL certificate: ' . $e->getMessage());
        }
    }
    
    /**
     * Get certificates that need renewal
     * 
     * @param int $daysBeforeExpiry Days before expiry to consider for renewal
     * @return array Array of certificate data with tracking item info
     */
    public function getCertificatesNeedingRenewal(int $daysBeforeExpiry = 30): array {
        $sql = "SELECT sc.*, ti.hostname, ti.port, ti.expiry_date
                FROM ssl_certificates sc
                JOIN tracking_items ti ON sc.tracking_item_id = ti.id
                WHERE sc.auto_renew = 1
                AND ti.expiry_date IS NOT NULL
                AND ti.expiry_date <= DATE_ADD(NOW(), INTERVAL :days DAY)
                AND ti.expiry_date > NOW()
                AND ti.status != 'error'
                ORDER BY ti.expiry_date ASC";
        
        try {
            return $this->db->fetchAll($sql, [':days' => $daysBeforeExpiry]);
        } catch (PDOException $e) {
            error_log('Failed to get certificates needing renewal: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get all certificates with their tracking item data
     * 
     * @param array $filters Optional filters
     * @return array Array of certificate data
     */
    public function getAllWithTrackingItems(array $filters = []): array {
        $sql = "SELECT sc.*, ti.name, ti.hostname, ti.port, ti.expiry_date, ti.status, ti.last_checked
                FROM ssl_certificates sc
                JOIN tracking_items ti ON sc.tracking_item_id = ti.id";
        
        $params = [];
        $conditions = [];
        
        // Apply filters
        if (!empty($filters['auto_renew'])) {
            $conditions[] = "sc.auto_renew = :auto_renew";
            $params[':auto_renew'] = $filters['auto_renew'];
        }
        
        if (!empty($filters['is_wildcard'])) {
            $conditions[] = "sc.is_wildcard = :is_wildcard";
            $params[':is_wildcard'] = $filters['is_wildcard'];
        }
        
        if (!empty($filters['status'])) {
            $conditions[] = "ti.status = :status";
            $params[':status'] = $filters['status'];
        }
        
        if (!empty($conditions)) {
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }
        
        $sql .= " ORDER BY ti.expiry_date ASC";
        
        try {
            return $this->db->fetchAll($sql, $params);
        } catch (PDOException $e) {
            error_log('Failed to get certificates with tracking items: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Update certificate file paths
     * 
     * @param int $id Certificate ID
     * @param array $paths Array of file paths
     * @return bool Success status
     */
    public function updateFilePaths(int $id, array $paths): bool {
        $sql = "UPDATE ssl_certificates SET 
                certificate_path = :certificate_path,
                private_key_path = :private_key_path,
                chain_path = :chain_path,
                updated_at = CURRENT_TIMESTAMP
                WHERE id = :id";
        
        $params = [
            ':id' => $id,
            ':certificate_path' => $paths['certificate_path'] ?? null,
            ':private_key_path' => $paths['private_key_path'] ?? null,
            ':chain_path' => $paths['chain_path'] ?? null,
        ];
        
        try {
            $affectedRows = $this->db->update($sql, $params);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            error_log('Failed to update certificate file paths: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Toggle auto-renewal for a certificate
     * 
     * @param int $id Certificate ID
     * @param bool $autoRenew Auto-renewal status
     * @return bool Success status
     */
    public function setAutoRenewal(int $id, bool $autoRenew): bool {
        $sql = "UPDATE ssl_certificates SET 
                auto_renew = :auto_renew,
                updated_at = CURRENT_TIMESTAMP
                WHERE id = :id";
        
        try {
            $affectedRows = $this->db->update($sql, [':id' => $id, ':auto_renew' => $autoRenew]);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            error_log('Failed to set auto-renewal: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get certificate statistics
     * 
     * @return array Statistics
     */
    public function getStatistics(): array {
        $sql = "SELECT 
            COUNT(*) as total_certificates,
            SUM(CASE WHEN is_wildcard = 1 THEN 1 ELSE 0 END) as wildcard_certificates,
            SUM(CASE WHEN auto_renew = 1 THEN 1 ELSE 0 END) as auto_renew_certificates,
            COUNT(DISTINCT issuer) as unique_issuers
        FROM ssl_certificates sc
        JOIN tracking_items ti ON sc.tracking_item_id = ti.id";
        
        try {
            $result = $this->db->fetchOne($sql);
            return $result ?: [
                'total_certificates' => 0,
                'wildcard_certificates' => 0,
                'auto_renew_certificates' => 0,
                'unique_issuers' => 0,
            ];
        } catch (PDOException $e) {
            error_log('Failed to get certificate statistics: ' . $e->getMessage());
            return [
                'total_certificates' => 0,
                'wildcard_certificates' => 0,
                'auto_renew_certificates' => 0,
                'unique_issuers' => 0,
            ];
        }
    }
}