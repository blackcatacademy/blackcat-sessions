<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Tests\Integration;

use BlackCat\Core\Database;
use BlackCat\Database\Crypto\IngressLocator;
use BlackCat\Database\Packages\Sessions\Repository\SessionRepository;
use BlackCat\Database\Packages\Sessions\SessionsModule;
use BlackCat\Database\Packages\Users\Repository\UserRepository;
use BlackCat\Database\Packages\Users\UsersModule;
use BlackCat\Database\Support\BinaryCodec;
use BlackCat\Sessions\SessionService;
use BlackCat\Sessions\Store\DatabaseSessionStore;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunClassInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * Requires a real DB (MySQL/Postgres); fails if a DB is not reachable.
 */
#[RunClassInSeparateProcess]
#[PreserveGlobalState(false)]
final class DatabaseSessionStoreIntegrationTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        // Reset global env for other tests.
        putenv('BLACKCAT_DB_ENCRYPTION_REQUIRED');
        putenv('BLACKCAT_DB_CRYPTO_REQUIRED');
        putenv('BLACKCAT_DB_ENCRYPTION_MAP');
        putenv('BLACKCAT_KEYS_DIR');
        putenv('BLACKCAT_CRYPTO_MANIFEST');

        if (class_exists(IngressLocator::class)) {
            IngressLocator::setAdapter(null);
            IngressLocator::configure(null, null);
        }
    }

    public function testDatabaseSessionStoreEndToEndWithCryptoIngress(): void
    {
        $db = $this->initDbOrFail();
        $dialect = $db->dialect();

        // Postgres views use digest(...) => requires pgcrypto extension.
        if (method_exists($dialect, 'isPg') && $dialect->isPg()) {
            $db->exec('CREATE EXTENSION IF NOT EXISTS pgcrypto;');
        }

        // Install schema packages required by the DB-backed store.
        (new UsersModule())->install($db, $dialect);
        (new SessionsModule())->install($db, $dialect);

        $this->wipeTables($db, ['sessions', 'users']);

        $mapPath = realpath(__DIR__ . '/../fixtures/encryption-map.json');
        $keysFixtureDir = realpath(__DIR__ . '/../fixtures/keys');
        $manifestPath = realpath(__DIR__ . '/../fixtures/manifest.json');
        if ($mapPath === false || $keysFixtureDir === false || $manifestPath === false) {
            self::fail('Test fixtures not available.');
        }

        $keysDir = $this->prepareKeysDir($keysFixtureDir);
        putenv('BLACKCAT_CRYPTO_MANIFEST=' . $manifestPath);
        putenv('BLACKCAT_DB_ENCRYPTION_REQUIRED=1');
        IngressLocator::configure($mapPath, $keysDir);
        self::assertNotNull(IngressLocator::adapter());

        $userId = $this->createUser($db);

        $store = new DatabaseSessionStore($db);
        $svc = new SessionService($store, ttl: 120);

        $issued = $svc->issue(['sub' => (string)$userId, 'roles' => ['customer']], [
            'ip' => '127.0.0.1',
            'user_agent' => 'phpunit',
        ]);

        $validated = $svc->validate($issued->id);
        self::assertNotNull($validated);
        self::assertSame((string)$userId, $validated->subject);

        $bySubject = $svc->sessionsFor((string)$userId);
        self::assertNotEmpty($bySubject);

        // Ensure write-path ingress actually transformed DB payload.
        $repo = new SessionRepository($db);
        $viewRow = $repo->getByTokenHash($issued->id, false);
        self::assertIsArray($viewRow);
        self::assertIsNumeric($viewRow['id'] ?? null);

        $storedTokenHash = BinaryCodec::toBinary($viewRow['token_hash'] ?? null);
        self::assertIsString($storedTokenHash);
        self::assertSame(32, strlen($storedTokenHash));
        self::assertNotSame($issued->id, $storedTokenHash);

        $storedFingerprint = BinaryCodec::toBinary($viewRow['token_fingerprint'] ?? null);
        self::assertIsString($storedFingerprint);
        self::assertSame(32, strlen($storedFingerprint));

        self::assertNotSame('', (string)($viewRow['token_hash_key_version'] ?? ''));
        self::assertNotSame('', (string)($viewRow['ip_hash_key_version'] ?? ''));

        $baseRow = $repo->findAllByIds([(int)$viewRow['id']])[0] ?? null;
        self::assertIsArray($baseRow);

        $storedBlob = BinaryCodec::toBinary($baseRow['session_blob'] ?? null);
        self::assertIsString($storedBlob);
        $storedBlobJson = json_decode($storedBlob, true);
        self::assertIsArray($storedBlobJson);
        self::assertArrayHasKey('local', $storedBlobJson);
        self::assertArrayHasKey('kms', $storedBlobJson);
        self::assertSame('core.vault', (string)($storedBlobJson['context'] ?? ''));

        // Simulate key rotation: add v2 key and re-bootstrap ingress (new process behavior).
        $this->rotateKeyInDir($keysDir);
        IngressLocator::setAdapter(null);
        IngressLocator::configure($mapPath, $keysDir);
        self::assertNotNull(IngressLocator::adapter());

        // Post-rotation HMAC lookup should fail, but validate() must still work via fingerprint fallback.
        $repoAfterRotation = new SessionRepository($db);
        self::assertNull($repoAfterRotation->getByTokenHash($issued->id, false));

        $svcAfterRotation = new SessionService(new DatabaseSessionStore($db), ttl: 120);
        $validatedAfterRotation = $svcAfterRotation->validate($issued->id);
        self::assertNotNull($validatedAfterRotation);
        self::assertSame((string)$userId, $validatedAfterRotation->subject);

        // Revocation should make validate() return null (also after rotation).
        $svcAfterRotation->revoke($issued->id);
        self::assertNull($svcAfterRotation->validate($issued->id));
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

    private function prepareKeysDir(string $fixtureDir): string
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-sessions-keys-' . bin2hex(random_bytes(6));
        if (!mkdir($tmp, 0700, true) && !is_dir($tmp)) {
            throw new \RuntimeException('Unable to create temp keys dir');
        }

        $src = rtrim($fixtureDir, '/\\') . '/crypto_key_v1.key';
        $dst = $tmp . '/crypto_key_v1.key';
        if (!is_file($src) || !copy($src, $dst)) {
            throw new \RuntimeException('Unable to seed temp keys dir');
        }

        return $tmp;
    }

    private function rotateKeyInDir(string $keysDir): void
    {
        $keysDir = rtrim($keysDir, '/\\');
        $path = $keysDir . '/crypto_key_v2.key';
        if (is_file($path)) {
            return;
        }
        $key = "fedcba9876543210fedcba9876543210";
        if (strlen($key) !== 32) {
            throw new \RuntimeException('Invalid v2 key length in test');
        }
        if (file_put_contents($path, $key) === false) {
            throw new \RuntimeException('Unable to write v2 key');
        }
    }
}
