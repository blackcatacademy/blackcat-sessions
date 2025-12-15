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
