<?php
/**
 * SSL & Domain Expiry Tracker - Database Connection Class
 * 
 * Handles database connections with error handling and connection pooling.
 * Implements singleton pattern for connection management.
 */

class Database {
    private static $instance = null;
    private $connection = null;
    private $host;
    private $database;
    private $username;
    private $password;
    private $charset;
    
    /**
     * Private constructor to prevent direct instantiation
     */
    private function __construct() {
        $this->host = DB_HOST;
        $this->database = DB_NAME;
        $this->username = DB_USER;
        $this->password = DB_PASS;
        $this->charset = DB_CHARSET;
        
        $this->connect();
    }
    
    /**
     * Get singleton instance of Database
     * 
     * @return Database
     */
    public static function getInstance(): Database {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Establish database connection with error handling
     * 
     * @throws Exception if connection fails
     */
    private function connect(): void {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->database};charset={$this->charset}";
            
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => true, // Connection pooling
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$this->charset}",
                PDO::ATTR_TIMEOUT => 30, // 30 second timeout
            ];
            
            $this->connection = new PDO($dsn, $this->username, $this->password, $options);
            
            // Test the connection
            $this->connection->query('SELECT 1');
            
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed: " . $e->getMessage());
        }
    }
    
    /**
     * Get the PDO connection instance
     * 
     * @return PDO
     */
    public function getConnection(): PDO {
        // Check if connection is still alive
        if ($this->connection === null) {
            $this->connect();
        }
        
        try {
            $this->connection->query('SELECT 1');
        } catch (PDOException $e) {
            // Connection lost, reconnect
            error_log("Database connection lost, reconnecting: " . $e->getMessage());
            $this->connect();
        }
        
        return $this->connection;
    }
    
    /**
     * Execute a prepared statement with parameters
     * 
     * @param string $query SQL query with placeholders
     * @param array $params Parameters for the query
     * @return PDOStatement
     * @throws Exception if query fails
     */
    public function execute(string $query, array $params = []): PDOStatement {
        try {
            $stmt = $this->getConnection()->prepare($query);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            error_log("Database query failed: " . $e->getMessage() . " Query: " . $query);
            throw new Exception("Database query failed: " . $e->getMessage());
        }
    }
    
    /**
     * Fetch a single row from the database
     * 
     * @param string $query SQL query
     * @param array $params Query parameters
     * @return array|false
     */
    public function fetchOne(string $query, array $params = []) {
        $stmt = $this->execute($query, $params);
        return $stmt->fetch();
    }
    
    /**
     * Fetch all rows from the database
     * 
     * @param string $query SQL query
     * @param array $params Query parameters
     * @return array
     */
    public function fetchAll(string $query, array $params = []): array {
        $stmt = $this->execute($query, $params);
        return $stmt->fetchAll();
    }
    
    /**
     * Insert a record and return the last insert ID
     * 
     * @param string $query SQL insert query
     * @param array $params Query parameters
     * @return string Last insert ID
     */
    public function insert(string $query, array $params = []): string {
        $this->execute($query, $params);
        return $this->getConnection()->lastInsertId();
    }
    
    /**
     * Update records and return affected row count
     * 
     * @param string $query SQL update query
     * @param array $params Query parameters
     * @return int Number of affected rows
     */
    public function update(string $query, array $params = []): int {
        $stmt = $this->execute($query, $params);
        return $stmt->rowCount();
    }
    
    /**
     * Delete records and return affected row count
     * 
     * @param string $query SQL delete query
     * @param array $params Query parameters
     * @return int Number of affected rows
     */
    public function delete(string $query, array $params = []): int {
        $stmt = $this->execute($query, $params);
        return $stmt->rowCount();
    }
    
    /**
     * Begin a database transaction
     * 
     * @return bool
     */
    public function beginTransaction(): bool {
        return $this->getConnection()->beginTransaction();
    }
    
    /**
     * Commit a database transaction
     * 
     * @return bool
     */
    public function commit(): bool {
        return $this->getConnection()->commit();
    }
    
    /**
     * Rollback a database transaction
     * 
     * @return bool
     */
    public function rollback(): bool {
        return $this->getConnection()->rollBack();
    }
    
    /**
     * Check if currently in a transaction
     * 
     * @return bool
     */
    public function inTransaction(): bool {
        return $this->getConnection()->inTransaction();
    }
    
    /**
     * Execute a transaction with automatic rollback on failure
     * 
     * @param callable $callback Function to execute within transaction
     * @return mixed Result of the callback function
     * @throws Exception if transaction fails
     */
    public function transaction(callable $callback) {
        $this->beginTransaction();
        
        try {
            $result = $callback($this);
            $this->commit();
            return $result;
        } catch (Exception $e) {
            $this->rollback();
            error_log("Transaction failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Get database server information
     * 
     * @return array
     */
    public function getServerInfo(): array {
        $connection = $this->getConnection();
        return [
            'server_version' => $connection->getAttribute(PDO::ATTR_SERVER_VERSION),
            'client_version' => $connection->getAttribute(PDO::ATTR_CLIENT_VERSION),
            'connection_status' => $connection->getAttribute(PDO::ATTR_CONNECTION_STATUS),
            'server_info' => $connection->getAttribute(PDO::ATTR_SERVER_INFO),
        ];
    }
    
    /**
     * Test database connection and return status
     * 
     * @return array Connection test results
     */
    public function testConnection(): array {
        try {
            $start_time = microtime(true);
            $result = $this->fetchOne('SELECT 1 as test, NOW() as current_time');
            $end_time = microtime(true);
            
            return [
                'status' => 'success',
                'response_time' => round(($end_time - $start_time) * 1000, 2), // milliseconds
                'server_time' => $result['current_time'],
                'test_result' => $result['test']
            ];
        } catch (Exception $e) {
            return [
                'status' => 'error',
                'error' => $e->getMessage(),
                'response_time' => null,
                'server_time' => null,
                'test_result' => null
            ];
        }
    }
    
    /**
     * Prevent cloning of the instance
     */
    private function __clone() {}
    
    /**
     * Prevent unserialization of the instance
     */
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}
?>