<?php
/**
 * SSL & Domain Expiry Tracker - TrackingItem Repository
 * 
 * Database access layer for tracking items with CRUD operations.
 * Implements data sanitization and SQL injection prevention.
 */

namespace App\Models;

use Database;
use Exception;
use PDO;
use PDOException;

class TrackingItemRepository {
    private Database $db;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->db = Database::getInstance();
    }
    
    /**
     * Create a new tracking item
     * 
     * @param TrackingItem $item
     * @return int The ID of the created item
     * @throws Exception if creation fails
     */
    public function create(TrackingItem $item): int {
        // Validate the item
        $errors = $item->validate();
        if (!empty($errors)) {
            throw new Exception('Validation failed: ' . implode(', ', $errors));
        }
        
        $sql = "INSERT INTO tracking_items (
            name, type, hostname, port, registrar, admin_emails, 
            expiry_date, last_checked, status, error_message
        ) VALUES (
            :name, :type, :hostname, :port, :registrar, :admin_emails,
            :expiry_date, :last_checked, :status, :error_message
        )";
        
        $params = [
            ':name' => $item->name,
            ':type' => $item->type,
            ':hostname' => $item->hostname,
            ':port' => $item->port,
            ':registrar' => $item->registrar,
            ':admin_emails' => $item->adminEmails ? json_encode($item->adminEmails) : null,
            ':expiry_date' => $item->expiryDate ? $item->expiryDate->format('Y-m-d H:i:s') : null,
            ':last_checked' => $item->lastChecked ? $item->lastChecked->format('Y-m-d H:i:s') : null,
            ':status' => $item->status,
            ':error_message' => $item->errorMessage,
        ];
        
        try {
            $id = $this->db->insert($sql, $params);
            $item->id = (int)$id;
            return (int)$id;
        } catch (PDOException $e) {
            throw new Exception('Failed to create tracking item: ' . $e->getMessage());
        }
    }
    
    /**
     * Find tracking item by ID
     * 
     * @param int $id
     * @return TrackingItem|null
     */
    public function findById(int $id): ?TrackingItem {
        $sql = "SELECT * FROM tracking_items WHERE id = :id";
        
        try {
            $data = $this->db->fetchOne($sql, [':id' => $id]);
            return $data ? new TrackingItem($data) : null;
        } catch (PDOException $e) {
            error_log('Failed to find tracking item by ID: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Find tracking item by hostname and type
     * 
     * @param string $hostname
     * @param string $type
     * @param int|null $port
     * @return TrackingItem|null
     */
    public function findByHostname(string $hostname, string $type, ?int $port = null): ?TrackingItem {
        $sql = "SELECT * FROM tracking_items WHERE hostname = :hostname AND type = :type";
        $params = [
            ':hostname' => $hostname,
            ':type' => $type,
        ];
        
        if ($type === 'ssl' && $port !== null) {
            $sql .= " AND port = :port";
            $params[':port'] = $port;
        }
        
        $sql .= " LIMIT 1";
        
        try {
            $data = $this->db->fetchOne($sql, $params);
            return $data ? new TrackingItem($data) : null;
        } catch (PDOException $e) {
            error_log('Failed to find tracking item by hostname: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Get all tracking items
     * 
     * @param array $filters Optional filters (type, status, etc.)
     * @param string $orderBy Order by field
     * @param string $orderDir Order direction (ASC/DESC)
     * @param int|null $limit Limit results
     * @param int $offset Offset for pagination
     * @return array Array of TrackingItem objects
     */
    public function findAll(
        array $filters = [], 
        string $orderBy = 'created_at', 
        string $orderDir = 'DESC',
        ?int $limit = null,
        int $offset = 0
    ): array {
        $sql = "SELECT * FROM tracking_items";
        $params = [];
        $conditions = [];
        
        // Apply filters
        if (!empty($filters['type'])) {
            $conditions[] = "type = :type";
            $params[':type'] = $filters['type'];
        }
        
        if (!empty($filters['status'])) {
            $conditions[] = "status = :status";
            $params[':status'] = $filters['status'];
        }
        
        if (!empty($filters['expiring_soon'])) {
            if ($filters['expiring_soon'] === 'ssl') {
                $conditions[] = "type = 'ssl' AND expiry_date <= DATE_ADD(NOW(), INTERVAL " . SSL_EXPIRY_WARNING_DAYS . " DAY) AND expiry_date > NOW()";
            } elseif ($filters['expiring_soon'] === 'domain') {
                $conditions[] = "type = 'domain' AND expiry_date <= DATE_ADD(NOW(), INTERVAL " . DOMAIN_EXPIRY_WARNING_DAYS . " DAY) AND expiry_date > NOW()";
            }
        }
        
        if (!empty($filters['expired'])) {
            $conditions[] = "expiry_date <= NOW()";
        }
        
        if (!empty($filters['search'])) {
            $conditions[] = "(name LIKE :search OR hostname LIKE :search)";
            $params[':search'] = '%' . $filters['search'] . '%';
        }
        
        // Add WHERE clause if conditions exist
        if (!empty($conditions)) {
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }
        
        // Add ORDER BY
        $allowedOrderFields = ['id', 'name', 'type', 'hostname', 'expiry_date', 'last_checked', 'status', 'created_at'];
        if (!in_array($orderBy, $allowedOrderFields)) {
            $orderBy = 'created_at';
        }
        
        $orderDir = strtoupper($orderDir) === 'ASC' ? 'ASC' : 'DESC';
        $sql .= " ORDER BY {$orderBy} {$orderDir}";
        
        // Add LIMIT and OFFSET
        if ($limit !== null) {
            $sql .= " LIMIT :limit OFFSET :offset";
            $params[':limit'] = $limit;
            $params[':offset'] = $offset;
        }
        
        try {
            $results = $this->db->fetchAll($sql, $params);
            return array_map(fn($data) => new TrackingItem($data), $results);
        } catch (PDOException $e) {
            error_log('Failed to fetch tracking items: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Update tracking item
     * 
     * @param TrackingItem $item
     * @return bool Success status
     * @throws Exception if update fails
     */
    public function update(TrackingItem $item): bool {
        if ($item->id === null) {
            throw new Exception('Cannot update item without ID');
        }
        
        // Validate the item
        $errors = $item->validate();
        if (!empty($errors)) {
            throw new Exception('Validation failed: ' . implode(', ', $errors));
        }
        
        $sql = "UPDATE tracking_items SET 
            name = :name,
            type = :type,
            hostname = :hostname,
            port = :port,
            registrar = :registrar,
            admin_emails = :admin_emails,
            expiry_date = :expiry_date,
            last_checked = :last_checked,
            status = :status,
            error_message = :error_message,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id";
        
        $params = [
            ':id' => $item->id,
            ':name' => $item->name,
            ':type' => $item->type,
            ':hostname' => $item->hostname,
            ':port' => $item->port,
            ':registrar' => $item->registrar,
            ':admin_emails' => $item->adminEmails ? json_encode($item->adminEmails) : null,
            ':expiry_date' => $item->expiryDate ? $item->expiryDate->format('Y-m-d H:i:s') : null,
            ':last_checked' => $item->lastChecked ? $item->lastChecked->format('Y-m-d H:i:s') : null,
            ':status' => $item->status,
            ':error_message' => $item->errorMessage,
        ];
        
        try {
            $affectedRows = $this->db->update($sql, $params);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            throw new Exception('Failed to update tracking item: ' . $e->getMessage());
        }
    }
    
    /**
     * Delete tracking item by ID
     * 
     * @param int $id
     * @return bool Success status
     * @throws Exception if deletion fails
     */
    public function delete(int $id): bool {
        $sql = "DELETE FROM tracking_items WHERE id = :id";
        
        try {
            $affectedRows = $this->db->delete($sql, [':id' => $id]);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            throw new Exception('Failed to delete tracking item: ' . $e->getMessage());
        }
    }
    
    /**
     * Get items that need monitoring (haven't been checked recently)
     * 
     * @param string $type Type of items to check ('ssl' or 'domain')
     * @param int $intervalHours Hours since last check
     * @return array Array of TrackingItem objects
     */
    public function getItemsNeedingCheck(string $type, int $intervalHours = 24): array {
        $sql = "SELECT * FROM tracking_items 
                WHERE type = :type 
                AND (last_checked IS NULL OR last_checked < DATE_SUB(NOW(), INTERVAL :interval HOUR))
                AND status != 'error'
                ORDER BY last_checked ASC";
        
        $params = [
            ':type' => $type,
            ':interval' => $intervalHours,
        ];
        
        try {
            $results = $this->db->fetchAll($sql, $params);
            return array_map(fn($data) => new TrackingItem($data), $results);
        } catch (PDOException $e) {
            error_log('Failed to get items needing check: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get items expiring soon
     * 
     * @param string $type Type of items ('ssl' or 'domain')
     * @return array Array of TrackingItem objects
     */
    public function getExpiringSoon(string $type): array {
        $warningDays = $type === 'ssl' ? SSL_EXPIRY_WARNING_DAYS : DOMAIN_EXPIRY_WARNING_DAYS;
        
        $sql = "SELECT * FROM tracking_items 
                WHERE type = :type 
                AND expiry_date IS NOT NULL
                AND expiry_date <= DATE_ADD(NOW(), INTERVAL :warning_days DAY)
                AND expiry_date > NOW()
                ORDER BY expiry_date ASC";
        
        $params = [
            ':type' => $type,
            ':warning_days' => $warningDays,
        ];
        
        try {
            $results = $this->db->fetchAll($sql, $params);
            return array_map(fn($data) => new TrackingItem($data), $results);
        } catch (PDOException $e) {
            error_log('Failed to get expiring items: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get expired items
     * 
     * @param string|null $type Optional type filter
     * @return array Array of TrackingItem objects
     */
    public function getExpired(?string $type = null): array {
        $sql = "SELECT * FROM tracking_items 
                WHERE expiry_date IS NOT NULL
                AND expiry_date <= NOW()";
        
        $params = [];
        
        if ($type !== null) {
            $sql .= " AND type = :type";
            $params[':type'] = $type;
        }
        
        $sql .= " ORDER BY expiry_date ASC";
        
        try {
            $results = $this->db->fetchAll($sql, $params);
            return array_map(fn($data) => new TrackingItem($data), $results);
        } catch (PDOException $e) {
            error_log('Failed to get expired items: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get dashboard statistics
     * 
     * @return array Statistics array
     */
    public function getDashboardStats(): array {
        $sql = "SELECT 
            COUNT(*) as total_items,
            SUM(CASE WHEN type = 'domain' THEN 1 ELSE 0 END) as total_domains,
            SUM(CASE WHEN type = 'ssl' THEN 1 ELSE 0 END) as total_ssl_certs,
            SUM(CASE WHEN type = 'domain' AND expiry_date <= DATE_ADD(NOW(), INTERVAL " . DOMAIN_EXPIRY_WARNING_DAYS . " DAY) AND expiry_date > NOW() THEN 1 ELSE 0 END) as domains_expiring_soon,
            SUM(CASE WHEN type = 'ssl' AND expiry_date <= DATE_ADD(NOW(), INTERVAL " . SSL_EXPIRY_WARNING_DAYS . " DAY) AND expiry_date > NOW() THEN 1 ELSE 0 END) as ssl_expiring_soon,
            SUM(CASE WHEN expiry_date <= NOW() THEN 1 ELSE 0 END) as expired_items,
            SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_items
        FROM tracking_items";
        
        try {
            $result = $this->db->fetchOne($sql);
            return $result ?: [
                'total_items' => 0,
                'total_domains' => 0,
                'total_ssl_certs' => 0,
                'domains_expiring_soon' => 0,
                'ssl_expiring_soon' => 0,
                'expired_items' => 0,
                'error_items' => 0,
            ];
        } catch (PDOException $e) {
            error_log('Failed to get dashboard stats: ' . $e->getMessage());
            return [
                'total_items' => 0,
                'total_domains' => 0,
                'total_ssl_certs' => 0,
                'domains_expiring_soon' => 0,
                'ssl_expiring_soon' => 0,
                'expired_items' => 0,
                'error_items' => 0,
            ];
        }
    }
    
    /**
     * Count total items with optional filters
     * 
     * @param array $filters
     * @return int
     */
    public function count(array $filters = []): int {
        $sql = "SELECT COUNT(*) as count FROM tracking_items";
        $params = [];
        $conditions = [];
        
        // Apply same filters as findAll
        if (!empty($filters['type'])) {
            $conditions[] = "type = :type";
            $params[':type'] = $filters['type'];
        }
        
        if (!empty($filters['status'])) {
            $conditions[] = "status = :status";
            $params[':status'] = $filters['status'];
        }
        
        if (!empty($filters['search'])) {
            $conditions[] = "(name LIKE :search OR hostname LIKE :search)";
            $params[':search'] = '%' . $filters['search'] . '%';
        }
        
        if (!empty($conditions)) {
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }
        
        try {
            $result = $this->db->fetchOne($sql, $params);
            return (int)($result['count'] ?? 0);
        } catch (PDOException $e) {
            error_log('Failed to count tracking items: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Update last checked timestamp for an item
     * 
     * @param int $id
     * @param string|null $status Optional status update
     * @param string|null $errorMessage Optional error message
     * @return bool
     */
    public function updateLastChecked(int $id, ?string $status = null, ?string $errorMessage = null): bool {
        $sql = "UPDATE tracking_items SET 
                last_checked = NOW(),
                updated_at = CURRENT_TIMESTAMP";
        
        $params = [':id' => $id];
        
        if ($status !== null) {
            $sql .= ", status = :status";
            $params[':status'] = $status;
        }
        
        if ($errorMessage !== null) {
            $sql .= ", error_message = :error_message";
            $params[':error_message'] = $errorMessage;
        }
        
        $sql .= " WHERE id = :id";
        
        try {
            $affectedRows = $this->db->update($sql, $params);
            return $affectedRows > 0;
        } catch (PDOException $e) {
            error_log('Failed to update last checked: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Bulk update expiry dates
     * 
     * @param array $updates Array of ['id' => int, 'expiry_date' => DateTime, 'status' => string]
     * @return int Number of updated items
     */
    public function bulkUpdateExpiry(array $updates): int {
        if (empty($updates)) {
            return 0;
        }
        
        $updated = 0;
        
        try {
            $this->db->beginTransaction();
            
            $sql = "UPDATE tracking_items SET 
                    expiry_date = :expiry_date,
                    status = :status,
                    last_checked = NOW(),
                    updated_at = CURRENT_TIMESTAMP
                    WHERE id = :id";
            
            foreach ($updates as $update) {
                $params = [
                    ':id' => $update['id'],
                    ':expiry_date' => $update['expiry_date']->format('Y-m-d H:i:s'),
                    ':status' => $update['status'],
                ];
                
                $affectedRows = $this->db->update($sql, $params);
                if ($affectedRows > 0) {
                    $updated++;
                }
            }
            
            $this->db->commit();
            
        } catch (Exception $e) {
            $this->db->rollback();
            error_log('Failed to bulk update expiry dates: ' . $e->getMessage());
        }
        
        return $updated;
    }
}