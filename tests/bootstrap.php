<?php
declare(strict_types=1);

$repoRoot = dirname(__DIR__);
$monorepoRoot = dirname($repoRoot);

// Monorepo helper: prefer local blackcat-core when present (lets us validate core fixes before pushing).
$localCoreDb = $monorepoRoot . '/blackcat-core/src/Database.php';
if (is_file($localCoreDb)) {
    require_once $localCoreDb;
}

$autoloadCandidates = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../blackcat-database/vendor/autoload.php',
    __DIR__ . '/../../blackcat-crypto/vendor/autoload.php',
    __DIR__ . '/../../blackcat-core/vendor/autoload.php',
];

$autoloadFound = false;
foreach ($autoloadCandidates as $candidate) {
    if (is_file($candidate)) {
        require $candidate;
        $autoloadFound = true;
        break;
    }
}

if (!$autoloadFound) {
    throw new RuntimeException('Cannot find an autoloader; run composer install or use the monorepo vendor.');
}

/**
 * Test-only guard rails:
 * - Do not require a full TrustKernel (trust.web3) setup for DB integration tests in this repo.
 * - Production deployments must bootstrap TrustKernel and lock guards; tests intentionally install permissive guards.
 */
if (class_exists('\\BlackCat\\Core\\Database')) {
    if (is_callable(['\\BlackCat\\Core\\Database', 'setWriteGuard'])) {
        \BlackCat\Core\Database::setWriteGuard(static function (string $_sql): void {});
    }
    if (is_callable(['\\BlackCat\\Core\\Database', 'setReadGuard'])) {
        \BlackCat\Core\Database::setReadGuard(static function (string $_sql): void {});
    }
    if (is_callable(['\\BlackCat\\Core\\Database', 'setPdoAccessGuard'])) {
        \BlackCat\Core\Database::setPdoAccessGuard(static function (string $_ctx): void {});
    }
}

/**
 * Helper to set env vars in a PHPUnit-friendly way.
 */
function bcsessions_tests_set_env(string $key, string $value): void
{
    if ($value === '') {
        return;
    }
    putenv($key . '=' . $value);
    $_ENV[$key] = $value;
    $_SERVER[$key] = $value;
}

/**
 * Auto-configure DB_DSN for DB integration tests when running on a known Docker network.
 *
 * This keeps integration tests fail-closed (they still fail if no DB is reachable),
 * but avoids requiring manual env export for the common dev setup.
 */
function bcsessions_tests_autoconfigure_db_env(): void
{
    $dsn = getenv('DB_DSN');
    if (is_string($dsn) && $dsn !== '') {
        return;
    }

    $user = getenv('DB_USER');
    if (!is_string($user) || $user === '') {
        $user = (string)(getenv('BC_TEST_DB_USER') ?: '');
    }

    $pass = getenv('DB_PASSWORD');
    if (!is_string($pass) || $pass === '') {
        $pass = (string)(getenv('BC_TEST_DB_PASS') ?: '');
    }

    $dbName = getenv('DB_NAME');
    if (!is_string($dbName) || $dbName === '') {
        $dbName = (string)(getenv('BC_TEST_DB_NAME') ?: 'blackcat_test');
    }

    if (extension_loaded('pdo_mysql')) {
        if ($user === '') {
            $user = 'root';
        }
        if ($pass === '') {
            $pass = 'root';
        }

        foreach (['bc-mysql-test', 'bc-mysql', 'mysql', 'mariadb'] as $host) {
            $candidate = sprintf('mysql:host=%s;port=3306;dbname=%s;charset=utf8mb4', $host, $dbName);
            try {
                $options = [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_TIMEOUT => 1,
                ];
                if (defined('\\PDO::MYSQL_ATTR_CONNECT_TIMEOUT')) {
                    $options[\PDO::MYSQL_ATTR_CONNECT_TIMEOUT] = 1;
                }
                $pdo = new \PDO($candidate, $user, $pass, $options);
                $pdo->query('SELECT 1');

                bcsessions_tests_set_env('DB_DSN', $candidate);
                bcsessions_tests_set_env('DB_USER', $user);
                bcsessions_tests_set_env('DB_PASSWORD', $pass);
                return;
            } catch (\Throwable) {
            }
        }
    }

    if (extension_loaded('pdo_pgsql')) {
        if ($user === '') {
            $user = 'postgres';
        }
        if ($pass === '') {
            $pass = 'postgres';
        }

        foreach (['bc-postgres-test', 'bc-postgres', 'postgres'] as $host) {
            $candidate = sprintf('pgsql:host=%s;port=5432;dbname=%s', $host, $dbName);
            try {
                $pdo = new \PDO($candidate, $user, $pass, [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_TIMEOUT => 1,
                ]);
                $pdo->query('SELECT 1');

                bcsessions_tests_set_env('DB_DSN', $candidate);
                bcsessions_tests_set_env('DB_USER', $user);
                bcsessions_tests_set_env('DB_PASSWORD', $pass);
                return;
            } catch (\Throwable) {
            }
        }
    }
}

bcsessions_tests_autoconfigure_db_env();

function bcsessions_register_psr4(string $prefix, string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    spl_autoload_register(static function (string $class) use ($prefix, $dir): void {
        if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
            return;
        }

        $relative = substr($class, strlen($prefix));
        $path = $dir . '/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($path)) {
            require $path;
        }
    }, true, true);
}

bcsessions_register_psr4('BlackCat\\Sessions\\', __DIR__ . '/../src');
bcsessions_register_psr4('BlackCat\\Database\\', __DIR__ . '/../../blackcat-database/src');
bcsessions_register_psr4('BlackCat\\Database\\Packages\\Users\\', __DIR__ . '/../../blackcat-database/packages/users/src');
bcsessions_register_psr4('BlackCat\\Database\\Packages\\Sessions\\', __DIR__ . '/../../blackcat-database/packages/sessions/src');
bcsessions_register_psr4('BlackCat\\DatabaseCrypto\\', __DIR__ . '/../../blackcat-database-crypto/src');
bcsessions_register_psr4('BlackCat\\Crypto\\', __DIR__ . '/../../blackcat-crypto/src');
bcsessions_register_psr4('BlackCat\\Core\\', __DIR__ . '/../../blackcat-core/src');

// Bootstrap a minimal `blackcat-config` runtime config for DB crypto ingress (fail-closed).
if (
    class_exists('\\BlackCat\\Config\\Runtime\\Config')
    && class_exists('\\BlackCat\\DatabaseCrypto\\Config\\PackagesEncryptionMapLoader')
    && !\BlackCat\Config\Runtime\Config::isInitialized()
) {
    $tmpRoot = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-sessions-tests-' . bin2hex(random_bytes(8));
    $keysDir = $tmpRoot . '/keys';
    $manifestPath = $tmpRoot . '/manifest.json';
    $runtimeConfigPath = $tmpRoot . '/config.runtime.json';

    if (!mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
        throw new RuntimeException('bootstrap: unable to create keys dir: ' . $keysDir);
    }

    $map = \BlackCat\DatabaseCrypto\Config\PackagesEncryptionMapLoader::fromAutodetectedBlackcatDatabaseRoot();
    $slots = [];

    foreach ($map->all() as $table => $cols) {
        foreach ($cols as $col => $spec) {
            if (!is_array($spec)) {
                continue;
            }

            $strategy = strtolower((string)($spec['strategy'] ?? 'passthrough'));
            if ($strategy === 'passthrough') {
                continue;
            }

            $context = $spec['context'] ?? null;
            if (!is_string($context) || trim($context) === '') {
                throw new RuntimeException(sprintf('bootstrap: missing context for %s.%s (strategy=%s)', (string)$table, (string)$col, $strategy));
            }

            $type = match ($strategy) {
                'encrypt' => 'aead',
                'hmac' => 'hmac',
                default => throw new RuntimeException(sprintf('bootstrap: unsupported strategy for %s.%s: %s', (string)$table, (string)$col, $strategy)),
            };
            $length = $type === 'hmac' ? 64 : 32;

            $keyBase = strtolower(preg_replace('~[^a-zA-Z0-9_.-]+~', '_', $context) ?: $context);
            $keyBase = strtolower(str_replace(['.', '-'], '_', $keyBase));
            $keyBase = trim($keyBase, '_');
            if ($keyBase === '') {
                throw new RuntimeException('bootstrap: unable to derive key basename for context: ' . $context);
            }
            if (strlen($keyBase) > 120) {
                $keyBase = substr($keyBase, 0, 96) . '_' . substr(hash('sha256', $keyBase), 0, 16);
            }

            $slots[$context] = [
                'type' => $type,
                'key' => $keyBase,
                'length' => $length,
            ];
        }
    }

    ksort($slots);

    foreach ($slots as $context => $def) {
        $keyName = (string)$def['key'];
        $length = (int)$def['length'];

        $file = $keysDir . '/' . $keyName . '_v1.key';
        if (file_put_contents($file, random_bytes($length)) === false) {
            throw new RuntimeException('bootstrap: unable to write key file: ' . $file);
        }
        @chmod($file, 0600);
    }

    $manifest = [
        'slots' => $slots,
        'rotation' => new stdClass(),
    ];
    $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false || file_put_contents($manifestPath, $json) === false) {
        throw new RuntimeException('bootstrap: unable to write manifest file: ' . $manifestPath);
    }
    @chmod($manifestPath, 0644);

    $runtime = [
        'crypto' => [
            'keys_dir' => $keysDir,
            'manifest' => $manifestPath,
        ],
    ];
    $json = json_encode($runtime, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false || file_put_contents($runtimeConfigPath, $json) === false) {
        throw new RuntimeException('bootstrap: unable to write runtime config file: ' . $runtimeConfigPath);
    }
    @chmod($runtimeConfigPath, 0600);

    \BlackCat\Config\Runtime\Config::initFromJsonFile($runtimeConfigPath);

    // Compatibility bridge: some repos still ship an env-based ingress loader (vendor blackcat-database).
    // Tests should work in both monorepo and standalone checkouts.
    bcsessions_tests_set_env('BLACKCAT_KEYS_DIR', $keysDir);
    bcsessions_tests_set_env('BLACKCAT_CRYPTO_MANIFEST', $manifestPath);
    bcsessions_tests_set_env('BLACKCAT_DB_ENCRYPTION_MAP', 'packages');
    bcsessions_tests_set_env('BLACKCAT_DB_CRYPTO_REQUIRED', '1');
}
