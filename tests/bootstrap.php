<?php
declare(strict_types=1);

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
}
