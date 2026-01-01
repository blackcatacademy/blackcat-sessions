<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Tests\Integration;

use BlackCat\Config\Runtime\Config as RuntimeConfig;
use BlackCat\Core\Database;
use BlackCat\Database\Crypto\IngressLocator;
use BlackCat\DatabaseCrypto\Config\PackagesEncryptionMapLoader;
use BlackCat\Database\Packages\Sessions\Repository\SessionRepository;
use BlackCat\Database\Packages\Sessions\SessionsModule;
use BlackCat\Database\Packages\Users\Repository\UserRepository;
use BlackCat\Database\Packages\Users\UsersModule;
use BlackCat\Database\Support\BinaryCodec;
use BlackCat\Sessions\Php\DbCachedSessionHandler;
use BlackCat\Sessions\Php\PhpSessionCodec;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunClassInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * Requires a real DB (MySQL/Postgres); fails if a DB is not reachable.
 */
#[RunClassInSeparateProcess]
#[PreserveGlobalState(false)]
final class DbCachedSessionHandlerIntegrationTest extends TestCase
{
    private function resetIngressLocator(): void
    {
        if (!class_exists(IngressLocator::class)) {
            return;
        }

        $ref = new \ReflectionClass(IngressLocator::class);

        foreach (['reset', 'configure'] as $method) {
            if ($ref->hasMethod($method)) {
                $ref->getMethod($method)->invoke(null);
                return;
            }
        }

        if ($ref->hasMethod('setAdapter')) {
            $ref->getMethod('setAdapter')->invoke(null, null);
        }
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        $this->resetIngressLocator();
    }

    public function testDbCachedSessionHandlerRoundTripAndRotation(): void
    {
        $db = $this->initDbOrFail();
        $dialect = $db->dialect();

        // Postgres views use digest(...) => requires pgcrypto extension.
        if (method_exists($dialect, 'isPg') && $dialect->isPg()) {
            $db->exec('CREATE EXTENSION IF NOT EXISTS pgcrypto;');
        }

        (new UsersModule())->install($db, $dialect);
        (new SessionsModule())->install($db, $dialect);

        $this->wipeTables($db, ['sessions', 'users']);

        IngressLocator::requireAdapter();

        $userId = $this->createUser($db);

        $handler = new DbCachedSessionHandler($db);
        $sessionId = 'sess_' . bin2hex(random_bytes(12));

        $sessionData = [
            'user_id' => $userId,
            'roles' => ['customer'],
            'flag' => false,
            'profile' => ['name' => 'Alice'],
        ];

        $payload = PhpSessionCodec::encode($sessionData);
        self::assertTrue($handler->write($sessionId, $payload));

        $outPayload = $handler->read($sessionId);
        $out = PhpSessionCodec::decode($outPayload);
        self::assertSame($sessionData, $out);

        // Validate DB payload is encrypted (envelope JSON stored in BYTEA/BLOB).
        $repo = new SessionRepository($db);
        $viewRow = $repo->getByTokenHash($sessionId, false);
        self::assertIsArray($viewRow);
        self::assertNotSame('', (string)($viewRow['token_hash_key_version'] ?? ''));
        self::assertMatchesRegularExpression('/_v1\\.key$/', (string)($viewRow['token_hash_key_version'] ?? ''));

        $baseRow = $repo->findAllByIds([(int)$viewRow['id']])[0] ?? null;
        self::assertIsArray($baseRow);
        $storedBlob = BinaryCodec::toBinary($baseRow['session_blob'] ?? null);
        self::assertIsString($storedBlob);
        $storedBlobJson = json_decode($storedBlob, true);
        self::assertIsArray($storedBlobJson);
        self::assertArrayHasKey('local', $storedBlobJson);
        self::assertArrayHasKey('kms', $storedBlobJson);
        self::assertSame('db.vault.sessions.session_blob', (string)($storedBlobJson['context'] ?? ''));

        // Simulate rotation: add v2 key and re-bootstrap ingress.
        $this->rotateTokenHashKey();
        $this->resetIngressLocator();
        IngressLocator::requireAdapter();

        $repoAfterRotation = new SessionRepository($db);
        self::assertNull($repoAfterRotation->getByTokenHash($sessionId, false));

        // Read still works via fingerprint fallback.
        $outPayload2 = $handler->read($sessionId);
        $out2 = PhpSessionCodec::decode($outPayload2);
        self::assertSame($sessionData, $out2);

        // Write should re-hash token_hash with the new key.
        self::assertTrue($handler->write($sessionId, $payload));
        $rehashRow = $repoAfterRotation->getByTokenHash($sessionId, false);
        self::assertIsArray($rehashRow);
        self::assertArrayHasKey('token_hash_key_version', $rehashRow);
        self::assertMatchesRegularExpression('/_v2\\.key$/', (string)$rehashRow['token_hash_key_version']);
    }

    private function initDbOrFail(): Database
    {
        $dsn = (string)(getenv('DB_DSN') ?: '');
        if ($dsn === '') {
            self::fail('Integration tests require a real DB. Set DB_DSN/DB_USER/DB_PASSWORD (use a disposable test database).');
        }

        Database::init([
            'dsn' => $dsn,
            'user' => getenv('DB_USER') ?: null,
            'pass' => getenv('DB_PASSWORD') ?: null,
        ]);

        return Database::getInstance();
    }

    private function createUser(Database $db): int
    {
        $repo = new UserRepository($db);
        $repo->insert([
            'password_hash' => 'x',
            'password_algo' => 'plaintext-test-only',
        ]);

        $id = $db->lastInsertId();
        if (is_string($id) && ctype_digit($id) && (int)$id > 0) {
            return (int)$id;
        }

        $row = $db->fetch('SELECT id FROM users ORDER BY id DESC LIMIT 1') ?: [];
        $val = $row['id'] ?? null;
        $userId = is_numeric($val) ? (int)$val : 0;
        if ($userId <= 0) {
            throw new \RuntimeException('Unable to determine inserted user id');
        }
        return $userId;
    }

    /**
     * @param list<string> $tables
     */
    private function wipeTables(Database $db, array $tables): void
    {
        foreach ($tables as $table) {
            $table = trim($table);
            if ($table === '') {
                continue;
            }
            try {
                $db->exec('DELETE FROM ' . $table);
            } catch (\Throwable) {
            }
        }
    }

    private function rotateTokenHashKey(): void
    {
        if (!RuntimeConfig::isInitialized()) {
            throw new \RuntimeException('Runtime config must be initialized by the test bootstrap.');
        }

        $map = PackagesEncryptionMapLoader::fromAutodetectedBlackcatDatabaseRoot();
        $cols = $map->columnsFor('sessions') ?? [];
        $spec = $cols['token_hash'] ?? $cols['TOKEN_HASH'] ?? null;
        if (!is_array($spec)) {
            throw new \RuntimeException('sessions.token_hash missing in encryption map (packages/*/schema/encryption-map.json)');
        }

        $context = $spec['context'] ?? null;
        if (!is_string($context) || trim($context) === '') {
            throw new \RuntimeException('sessions.token_hash has no context in encryption map');
        }

        $repo = RuntimeConfig::repo();
        $keysDir = $repo->resolvePath($repo->requireString('crypto.keys_dir'));
        $manifestPath = $repo->resolvePath($repo->requireString('crypto.manifest'));

        $raw = file_get_contents($manifestPath);
        if ($raw === false) {
            throw new \RuntimeException('Unable to read manifest: ' . $manifestPath);
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || !is_array($decoded['slots'] ?? null)) {
            throw new \RuntimeException('Invalid manifest JSON: ' . $manifestPath);
        }

        /** @var array<string,mixed> $slots */
        $slots = $decoded['slots'];
        $slot = $slots[$context] ?? null;
        if (!is_array($slot)) {
            throw new \RuntimeException('sessions.token_hash context is missing in manifest slots: ' . $context);
        }

        $keyBase = $slot['key'] ?? null;
        $length = $slot['length'] ?? null;
        if (!is_string($keyBase) || $keyBase === '' || !is_int($length) || $length <= 0) {
            throw new \RuntimeException('Invalid slot definition for context ' . $context);
        }

        $path = rtrim($keysDir, '/\\') . '/' . $keyBase . '_v2.key';
        if (is_file($path)) {
            return;
        }

        if (file_put_contents($path, random_bytes($length)) === false) {
            throw new \RuntimeException('Unable to write v2 key: ' . $path);
        }
        @chmod($path, 0600);
    }
}
