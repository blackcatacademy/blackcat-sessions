# BlackCat Sessions

`blackcat-sessions` je samostatný modul pro session logiku v ekosystému BlackCat.

- DB-backed sessions přes `blackcat-database` (generated repositories).
- Crypto ingress přes `blackcat-database-crypto` (HMAC pro lookup + šifrování `session_blob`, fail-closed).
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

- V `blackcat-database` je šifrování/HMAC řešeno přes `IngressLocator` a mapy v `packages/*/schema/encryption-map.json` (single source of truth).
- Pro běh je potřeba runtime config (doporučené přes `blackcat-config`) s minimem:
  - `crypto.keys_dir` (required)
  - `crypto.manifest` (optional; pro slot metadata / konzistenci)
- V produkci je cílem držet klíče mimo web runtime (secrets-agent boundary), a runtime config mít mimo web docroot (např. `/etc/blackcat/config.runtime.json`).

Roadmap: `docs/ROADMAP.md`.
