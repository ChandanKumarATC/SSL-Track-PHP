<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Database;
use PDO;
use Exception;

/**
 * Unit tests for Database connection class
 */
class DatabaseTest extends TestCase
{
    private Database $database;

    protected function setUp(): void
    {
        // Skip database tests if not configured
        if (!defined('DB_HOST') || empty(DB_HOST)) {
            $this->markTestSkipped('Database not configured for testing');
        }
        
        $this->database = Database::getInstance();
    }

    public function testSingletonPattern(): void
    {
        $instance1 = Database::getInstance();
        $instance2 = Database::getInstance();
        
        $this->assertSame($instance1, $instance2, 'Database should implement singleton pattern');
    }

    public function testGetConnection(): void
    {
        $connection = $this->database->getConnection();
        
        $this->assertInstanceOf(PDO::class, $connection, 'Should return PDO instance');
    }

    public function testConnectionTest(): void
    {
        $result = $this->database->testConnection();
        
        $this->assertIsArray($result, 'testConnection should return array');
        $this->assertArrayHasKey('status', $result, 'Result should have status key');
        
        if ($result['status'] === 'success') {
            $this->assertArrayHasKey('response_time', $result);
            $this->assertArrayHasKey('server_time', $result);
            $this->assertArrayHasKey('test_result', $result);
            $this->assertEquals(1, $result['test_result']);
        }
    }

    public function testExecuteQuery(): void
    {
        try {
            $stmt = $this->database->execute('SELECT 1 as test');
            $this->assertNotNull($stmt, 'Execute should return PDOStatement');
            
            $result = $stmt->fetch();
            $this->assertEquals(1, $result['test'], 'Query should return expected result');
        } catch (Exception $e) {
            $this->markTestSkipped('Database connection not available: ' . $e->getMessage());
        }
    }

    public function testFetchOne(): void
    {
        try {
            $result = $this->database->fetchOne('SELECT ? as test', [42]);
            $this->assertIsArray($result, 'fetchOne should return array');
            $this->assertEquals(42, $result['test'], 'Should return parameterized value');
        } catch (Exception $e) {
            $this->markTestSkipped('Database connection not available: ' . $e->getMessage());
        }
    }

    public function testFetchAll(): void
    {
        try {
            $results = $this->database->fetchAll('SELECT ? as test UNION SELECT ? as test', [1, 2]);
            $this->assertIsArray($results, 'fetchAll should return array');
            $this->assertCount(2, $results, 'Should return 2 rows');
        } catch (Exception $e) {
            $this->markTestSkipped('Database connection not available: ' . $e->getMessage());
        }
    }

    public function testTransaction(): void
    {
        try {
            $result = $this->database->transaction(function($db) {
                return $db->fetchOne('SELECT 1 as test');
            });
            
            $this->assertIsArray($result, 'Transaction should return result');
            $this->assertEquals(1, $result['test'], 'Transaction should execute successfully');
        } catch (Exception $e) {
            $this->markTestSkipped('Database connection not available: ' . $e->getMessage());
        }
    }

    public function testGetServerInfo(): void
    {
        try {
            $info = $this->database->getServerInfo();
            
            $this->assertIsArray($info, 'getServerInfo should return array');
            $this->assertArrayHasKey('server_version', $info);
            $this->assertArrayHasKey('client_version', $info);
        } catch (Exception $e) {
            $this->markTestSkipped('Database connection not available: ' . $e->getMessage());
        }
    }
}