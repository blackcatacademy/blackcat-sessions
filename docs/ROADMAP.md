# BlackCat Sessions – Roadmap

## Stage 1 – Foundations (this PR)
- Základní `SessionService` + store interface.
- In-memory store (unit testy).
- Připravit DB store nad `blackcat-database` (`sessions` package) + crypto ingress.

## Stage 2 – DB-backed + crypto
- `DatabaseSessionStore` s deterministickým lookupem (`token_hash`) přes ingress criteria.
- Šifrování `session_blob` přes ingress (bez vlastního Crypto/KeyManager v modulu).
- Integrační test (MySQL/Postgres; skip bez `DB_DSN`).

## Stage 3 – Web/PHP integration
- Cookie helper + shim v `blackcat-core` (`SessionManager`) delegující na `blackcat-sessions`.
- Podpora rotace klíčů: fallback lookup přes `token_fingerprint` (když se změní aktivní HMAC key).
- `DbCachedSessionHandler` jako `\SessionHandlerInterface` (DB-backed přes `sessions` package + volitelný ingress decrypt/encrypt).
- Integrační test: round-trip + simulace rotace klíče (fallback lookup + re-hash na write).

## Stage 4 – Hardening / ergonomie
- Volitelný cache stampede lock pro `read()` (pokud je cache `LockingCacheInterface`).
- Rozšířit docs o doporučené mapování polí v `encryption-map.json` (token/ip HMAC + session_blob encrypt).
