# BlackCat Sessions

`blackcat-sessions` je samostatný modul pro session logiku v ekosystému BlackCat.

- DB-backed sessions přes `blackcat-database` (generated repositories).
- Volitelný crypto ingress přes `blackcat-database-crypto` (HMAC pro lookup + šifrování `session_blob`).
- Cíl: `blackcat-auth` ani `blackcat-core` nemusí mít vlastní session implementaci.

## Instalace

```bash
composer require blackcatacademy/blackcat-sessions
```

## Rychlé použití (Auth-like sessions)

```php
use BlackCat\Core\Database;
use BlackCat\Sessions\SessionService;
use BlackCat\Sessions\Store\SessionStoreFactory;

Database::init([
  'dsn' => getenv('DB_DSN'),
  'user' => getenv('DB_USER') ?: null,
  'pass' => getenv('DB_PASSWORD') ?: null,
]);

$store = SessionStoreFactory::fromConfig(['type' => 'database'], Database::getInstance());
$sessions = new SessionService($store, ttl: 3600);

$session = $sessions->issue(['sub' => '123', 'roles' => ['customer']], ['ip' => $_SERVER['REMOTE_ADDR'] ?? null]);
```

## Native PHP sessions (`\SessionHandlerInterface`)

Pokud chceš používat klasické `$_SESSION` a `session_start()`, použij DB-backed handler:

```php
use BlackCat\Core\Database;
use BlackCat\Sessions\Php\DbCachedSessionHandler;

Database::init([
  'dsn' => getenv('DB_DSN'),
  'user' => getenv('DB_USER') ?: null,
  'pass' => getenv('DB_PASSWORD') ?: null,
]);

$handler = new DbCachedSessionHandler(Database::getInstance());
session_set_save_handler($handler, true);
session_start();
```

Handler ukládá session do `blackcat-database` package `sessions` (sloupec `session_blob`), a pokud je nakonfigurován ingress (`blackcat-database-crypto`), tak se payload šifruje/HMACuje transparentně.

## Legacy PHP kompatibilita (shim pro `blackcat-core`)

`blackcat-core` nyní obsahuje pouze shim, který deleguje na `blackcat-sessions`:

```php
use BlackCat\Core\Database;
use BlackCat\Core\Session\SessionManager; // shim -> BlackCat\\Sessions\\Php\\SessionManager

$token = SessionManager::createSession(Database::getInstance(), $userId);
$userId = SessionManager::validateSession(Database::getInstance());
SessionManager::destroySession(Database::getInstance());
```

## Poznámky ke crypto ingress

- Doporučené: nastavit `BLACKCAT_DB_ENCRYPTION_REQUIRED=1` a mít v mapě tabulku `sessions` pro:
  - `token_hash` (HMAC)
  - `ip_hash` (HMAC)
  - `session_blob` (ENCRYPT)

Roadmap: `docs/ROADMAP.md`.
