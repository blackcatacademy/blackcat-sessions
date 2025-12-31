<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Php;

use BlackCat\Core\Database;
use BlackCat\Database\Crypto\IngressLocator;
use BlackCat\Database\Packages\Sessions\Criteria as SessionsCriteria;
use BlackCat\Database\Packages\Sessions\Repository\SessionRepository;
use BlackCat\Database\Support\BinaryCodec;
use Psr\SimpleCache\CacheInterface;
use BlackCat\Core\Cache\LockingCacheInterface;

/**
 * DB-backed PHP session handler (no raw PDO/SQL).
 *
 * Storage: `blackcat-database` package `sessions`.
 * Optional crypto: `blackcat-database-crypto` ingress (HMAC for lookups + encrypt `session_blob`).
 */
final class DbCachedSessionHandler implements \SessionHandlerInterface
{
    private const DEFAULT_TABLE = 'sessions';

    private SessionRepository $sessions;

    public function __construct(
        private readonly Database $db,
        ?CacheInterface $cache = null,
        string $tableName = 'sessions',
        int $cacheTtlSeconds = 120
    ) {
        $tableName = trim($tableName);
        if ($tableName === '') {
            $tableName = self::DEFAULT_TABLE;
        }
        if ($tableName !== self::DEFAULT_TABLE) {
            throw new \InvalidArgumentException('DbCachedSessionHandler currently supports only table "sessions" (blackcat-database package).');
        }

        $this->cache = $cache;
        $this->cacheTtlSeconds = max(0, $cacheTtlSeconds);
        $this->sessions = new SessionRepository($db);

        // Fail fast: sessions are expected to run with DB crypto ingress enabled.
        IngressLocator::requireAdapter();
    }

    private ?CacheInterface $cache;
    private int $cacheTtlSeconds;
    private int $lockTtlSeconds = 5;

    public function open(string $savePath, string $sessionName): bool
    {
        unset($savePath, $sessionName);
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string
    {
        $sessionId = trim($id);
        if ($sessionId === '') {
            return '';
        }

        $cacheKey = $this->cacheKey($sessionId);
        if ($this->cache !== null) {
            $cached = $this->cacheGet($cacheKey);
            if (is_array($cached) && isset($cached['blob']) && is_string($cached['blob'])) {
                $meta = is_array($cached['meta'] ?? null) ? (array)$cached['meta'] : [];
                if (!empty($meta['revoked'])) {
                    return '';
                }
                $expiresAt = is_string($meta['expires_at'] ?? null) ? (string)$meta['expires_at'] : null;
                if ($expiresAt !== null && $this->isExpiredSqlDateTime($expiresAt)) {
                    return '';
                }

                $plain = $this->decryptSessionBlob($cached['blob']);
                $payload = $plain !== null ? $this->convertPlainToSessionPayload($plain) : null;
                if ($payload !== null) {
                    return $payload;
                }
            }
        }

        $rowId = $this->resolveRowIdForToken($sessionId);
        if ($rowId <= 0) {
            return '';
        }

        $rows = $this->sessions->findAllByIds([$rowId]);
        $row = $rows[0] ?? null;
        if (!is_array($row)) {
            return '';
        }

        if (!empty($row['revoked'])) {
            return '';
        }

        $expiresAt = is_string($row['expires_at'] ?? null) ? (string)$row['expires_at'] : null;
        if ($expiresAt !== null && $this->isExpiredSqlDateTime($expiresAt)) {
            return '';
        }

        $blob = BinaryCodec::toBinary($row['session_blob'] ?? null);
        if (!is_string($blob) || $blob === '') {
            return '';
        }

        $plain = $this->decryptSessionBlob($blob);
        $payload = $plain !== null ? $this->convertPlainToSessionPayload($plain) : null;
        if ($payload === null) {
            $this->recordDecryptFailure($rowId, $row);
            return '';
        }

        $this->cachePut($cacheKey, $blob, [
            'expires_at' => $expiresAt,
            'revoked' => (bool)($row['revoked'] ?? false),
        ]);

        return $payload;
    }

    public function write(string $id, string $data): bool
    {
        $sessionId = trim($id);
        if ($sessionId === '') {
            return false;
        }

        $handler = (string)(ini_get('session.serialize_handler') ?: 'php');
        $plaintext = null;

        if ($handler === 'php') {
            $parsed = PhpSessionCodec::decode($data);
            if (is_array($parsed)) {
                $clean = PhpSessionCodec::sanitize($parsed);
                $json = json_encode($clean, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                if ($json === false) {
                    return false;
                }
                $plaintext = $json;
            }
        }

        // Fallback for unsupported serialize handlers or parse failures.
        if (!is_string($plaintext)) {
            $plaintext = $data;
        }

        $userId = null;
        if (isset($parsed) && is_array($parsed)) {
            $maybeUserId = $parsed['user_id'] ?? $parsed['uid'] ?? null;
            if (is_int($maybeUserId) && $maybeUserId > 0) {
                $userId = $maybeUserId;
            } elseif (is_string($maybeUserId) && ctype_digit($maybeUserId) && (int)$maybeUserId > 0) {
                $userId = (int)$maybeUserId;
            }
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        $ip = is_string($ip) ? trim($ip) : null;
        if ($ip === '') {
            $ip = null;
        }

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $ua = is_string($ua) ? trim($ua) : null;
        if ($ua === '') {
            $ua = null;
        }

        $now = time();
        $issuedAt = $this->formatSqlDateTimeFromEpoch($now);
        $expiresAt = $this->formatSqlDateTimeFromEpoch($now + $this->sessionLifetimeSeconds());
        $fingerprint = hash('sha256', $sessionId, true);

        $rowId = $this->resolveRowIdForToken($sessionId);

        try {
            if ($rowId > 0) {
                $payload = [
                    'token_hash' => $sessionId,
                    'token_fingerprint' => $fingerprint,
                    'last_seen_at' => $issuedAt,
                    'expires_at' => $expiresAt,
                    'session_blob' => $plaintext,
                    'ip_hash' => $ip,
                    'user_agent' => $ua,
                ];
                if ($userId !== null) {
                    $payload['user_id'] = $userId;
                }
                $this->sessions->updateById($rowId, $payload);
            } else {
                $payload = [
                    'token_hash' => $sessionId,
                    'token_fingerprint' => $fingerprint,
                    'token_issued_at' => $issuedAt,
                    'user_id' => $userId,
                    'expires_at' => $expiresAt,
                    'revoked' => false,
                    'ip_hash' => $ip,
                    'user_agent' => $ua,
                    'session_blob' => $plaintext,
                ];
                $this->sessions->insert($payload);
            }
        } catch (\Throwable $e) {
            throw $e;
        }

        if ($this->cache !== null) {
            $this->cacheDelete($this->cacheKey($sessionId));
        }

        return true;
    }

    public function destroy(string $id): bool
    {
        $sessionId = trim($id);
        if ($sessionId === '') {
            return true;
        }

        $rowId = $this->resolveRowIdForToken($sessionId);
        if ($rowId > 0) {
            try {
                $this->sessions->deleteById($rowId);
            } catch (\Throwable $e) {
                throw $e;
            }
        }

        if ($this->cache !== null) {
            $this->cacheDelete($this->cacheKey($sessionId));
        }

        return true;
    }

    public function gc(int $max_lifetime): int|false
    {
        $max_lifetime = max(0, $max_lifetime);
        if ($max_lifetime <= 0) {
            return 0;
        }

        $cut = $this->formatSqlDateTimeFromEpoch(time() - $max_lifetime);
        $deleted = 0;

        // Conservative approach: select IDs via Criteria and delete them.
        // This avoids raw SQL and stays within blackcat-database abstractions.
        while (true) {
            $crit = SessionsCriteria::fromDb($this->db)
                ->isNotNull('expires_at')
                ->where('expires_at', '<', $cut)
                ->setPerPage(200)
                ->setPage(1);

            $page = $this->sessions->paginate($crit);
            $items = is_array($page['items'] ?? null) ? $page['items'] : [];
            if ($items === []) {
                break;
            }

            foreach ($items as $row) {
                if (!is_array($row) || !isset($row['id'])) {
                    continue;
                }
                $idVal = (int)$row['id'];
                if ($idVal <= 0) {
                    continue;
                }
                try {
                    $deleted += $this->sessions->deleteById($idVal) > 0 ? 1 : 0;
                } catch (\Throwable) {
                }
            }
        }

        return $deleted;
    }

    // ------------------------- internal helpers -------------------------

    private function cacheKey(string $sessionId): string
    {
        return 'blackcat:sessions:php:' . hash('sha256', $sessionId);
    }

    private function cacheGet(string $key): mixed
    {
        try {
            return $this->cache?->get($key);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @param array<string,mixed> $meta
     */
    private function cachePut(string $key, string $blob, array $meta): void
    {
        if ($this->cache === null || $this->cacheTtlSeconds <= 0) {
            return;
        }

        // Only cache when crypto ingress is available to ensure cache never stores plaintext sensitive data.
        IngressLocator::requireAdapter();

        $ttl = $this->computeCacheTtlFromExpires(is_string($meta['expires_at'] ?? null) ? (string)$meta['expires_at'] : null);
        if ($ttl === 0) {
            return;
        }

        $payload = ['blob' => $blob, 'meta' => $meta];

        if ($this->cache instanceof LockingCacheInterface) {
            $lockName = 'blackcat:sessions:php:lock:' . hash('sha256', $key);
            $token = null;
            try {
                $token = $this->cache->acquireLock($lockName, $this->lockTtlSeconds);
                $this->cache->set($key, $payload, $ttl);
            } catch (\Throwable) {
            } finally {
                if ($token !== null) {
                    try {
                        $this->cache->releaseLock($lockName, $token);
                    } catch (\Throwable) {
                    }
                }
            }
            return;
        }

        try {
            $this->cache->set($key, $payload, $ttl);
        } catch (\Throwable) {
        }
    }

    private function cacheDelete(string $key): void
    {
        try {
            $this->cache?->delete($key);
        } catch (\Throwable) {
        }
    }

    private function computeCacheTtlFromExpires(?string $expiresAt): ?int
    {
        if ($this->cacheTtlSeconds <= 0) {
            return null;
        }
        if ($expiresAt === null || $expiresAt === '') {
            return $this->cacheTtlSeconds;
        }
        try {
            $exp = new \DateTimeImmutable($expiresAt, new \DateTimeZone('UTC'));
            $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
            $secs = $exp->getTimestamp() - $now->getTimestamp();
            if ($secs <= 0) {
                return 0;
            }
            return min($this->cacheTtlSeconds, $secs);
        } catch (\Throwable) {
            return $this->cacheTtlSeconds;
        }
    }

    private function isExpiredSqlDateTime(string $expiresAt): bool
    {
        try {
            $exp = new \DateTimeImmutable($expiresAt, new \DateTimeZone('UTC'));
            return $exp < new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        } catch (\Throwable) {
            return false;
        }
    }

    private function sessionLifetimeSeconds(): int
    {
        $v = (int)ini_get('session.gc_maxlifetime');
        return max(60, $v);
    }

    private function formatSqlDateTimeFromEpoch(int $epochSec): string
    {
        $epochSec = max(0, $epochSec);
        $dt = (new \DateTimeImmutable('@' . $epochSec))->setTimezone(new \DateTimeZone('UTC'));
        return $dt->format('Y-m-d H:i:s.u');
    }

    /**
     * Resolve the DB row id for a plaintext token.
     *
     * - Primary: HMAC-based unique lookup via `token_hash` (through ingress criteria).
     * - Fallback: `token_fingerprint` (sha256) to survive HMAC key rotation.
     */
    private function resolveRowIdForToken(string $token): int
    {
        $token = trim($token);
        if ($token === '') {
            return 0;
        }

        $row = $this->sessions->getByTokenHash($token, false);
        if (is_array($row) && isset($row['id'])) {
            $id = (int)$row['id'];
            if ($id > 0) {
                return $id;
            }
        }

        $fingerprint = hash('sha256', $token, true);
        $crit = SessionsCriteria::fromDb($this->db)
            ->where('token_fingerprint', '=', $fingerprint)
            ->orderBy('created_at', 'DESC')
            ->setPerPage(1)
            ->setPage(1);

        $page = $this->sessions->paginate($crit);
        $items = is_array($page['items'] ?? null) ? $page['items'] : [];
        $first = $items[0] ?? null;
        if (!is_array($first) || !isset($first['id'])) {
            return 0;
        }

        $id = (int)$first['id'];
        return $id > 0 ? $id : 0;
    }

    private function decryptSessionBlob(string $blob): ?string
    {
        $blob = BinaryCodec::toBinary($blob) ?? '';
        if ($blob === '') {
            return null;
        }

        $adapter = IngressLocator::adapter();

        if ($adapter !== null && method_exists($adapter, 'decrypt')) {
            try {
                /** @var array<string,mixed> $out */
                $out = $adapter->decrypt('sessions', ['session_blob' => $blob], ['strict' => false]);
                $maybe = $out['session_blob'] ?? null;
                $decoded = BinaryCodec::toBinary($maybe);
                if (is_string($decoded) && $decoded !== '') {
                    $blob = $decoded;
                }
            } catch (\Throwable) {
            }
        }

        return $blob;
    }

    private function convertPlainToSessionPayload(string $plain): ?string
    {
        $plain = trim($plain);
        if ($plain === '') {
            return '';
        }

        $handler = (string)(ini_get('session.serialize_handler') ?: 'php');
        if ($handler !== 'php') {
            return $plain;
        }

        $maybe = json_decode($plain, true);
        if (!is_array($maybe)) {
            return $plain;
        }

        // If this looks like an encryption envelope (crypto not configured / decrypt failed), treat as invalid.
        if (
            isset($maybe['local'], $maybe['kms'], $maybe['context'])
            && is_array($maybe['local'])
            && is_array($maybe['kms'])
        ) {
            return null;
        }

        /** @var array<string,mixed> $maybe */
        return PhpSessionCodec::encode($maybe);
    }

    /**
     * @param array<string,mixed> $row
     */
    private function recordDecryptFailure(int $rowId, array $row): void
    {
        $count = isset($row['failed_decrypt_count']) ? (int)$row['failed_decrypt_count'] : 0;
        $count = max(0, $count) + 1;
        $now = $this->formatSqlDateTimeFromEpoch(time());

        try {
            $this->sessions->updateById($rowId, [
                'failed_decrypt_count' => $count,
                'last_failed_decrypt_at' => $now,
                'last_seen_at' => $now,
            ]);
        } catch (\Throwable) {
        }
    }
}
