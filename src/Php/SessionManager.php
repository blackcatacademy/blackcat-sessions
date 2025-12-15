<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Php;

use BlackCat\Core\Database;
use BlackCat\Sessions\SessionService;
use BlackCat\Sessions\Store\DatabaseSessionStore;
use Psr\SimpleCache\CacheInterface;

/**
 * Compatibility layer for legacy PHP apps that expect a static SessionManager.
 *
 * This implementation avoids raw PDO/SQL and stores sessions via the generated
 * `blackcat-database` sessions repository + optional crypto ingress.
 */
final class SessionManager
{
    private const COOKIE_NAME = 'session_token';

    private static ?CacheInterface $cache = null;
    private static int $cacheTtlSeconds = 120;

    private function __construct() {}

    public static function initCache(CacheInterface $cache, int $ttlSeconds = 120): void
    {
        self::$cache = $cache;
        self::$cacheTtlSeconds = max(0, $ttlSeconds);
    }

    public static function createSession(
        Database $db,
        int $userId,
        int $days = 30,
        bool $allowMultiple = true,
        string $samesite = 'Lax'
    ): string {
        if ($userId <= 0) {
            throw new \InvalidArgumentException('user_id_must_be_positive');
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;

        $ttlSec = max(0, $days) * 86400;
        $store = new DatabaseSessionStore($db);
        $svc = new SessionService($store, $ttlSec);

        if (!$allowMultiple) {
            foreach ($svc->sessionsFor((string)$userId) as $existing) {
                $svc->revoke($existing->id);
            }
        }

        $session = $svc->issue(
            ['sub' => (string)$userId],
            [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            ]
        );

        self::setCookie($session->id, $session->expiresAt, $samesite);
        self::cachePutUserId($session->id, $userId, $session->expiresAt);

        return $session->id;
    }

    public static function validateSession(Database $db): ?int
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $token = $_COOKIE[self::COOKIE_NAME] ?? null;
        $token = is_string($token) ? trim($token) : '';
        if ($token === '') {
            return null;
        }

        $cached = self::cacheGetUserId($token);
        if ($cached !== null) {
            $_SESSION['user_id'] = $cached;
            return $cached;
        }

        $svc = new SessionService(new DatabaseSessionStore($db));
        $record = $svc->validate($token);
        if ($record === null || !ctype_digit($record->subject)) {
            return null;
        }

        $userId = (int)$record->subject;
        if ($userId <= 0) {
            return null;
        }

        $_SESSION['user_id'] = $userId;
        self::cachePutUserId($token, $userId, $record->expiresAt);
        return $userId;
    }

    public static function destroySession(Database $db): void
    {
        $token = $_COOKIE[self::COOKIE_NAME] ?? null;
        $token = is_string($token) ? trim($token) : '';

        if ($token !== '') {
            $svc = new SessionService(new DatabaseSessionStore($db));
            $svc->revoke($token);
            self::cacheDelete($token);
        }

        self::clearCookie();

        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            session_regenerate_id(true);
        }
    }

    private static function setCookie(string $token, int $expiresAt, string $samesite): void
    {
        $samesite = in_array($samesite, ['Lax', 'Strict', 'None'], true) ? $samesite : 'Lax';

        if (!headers_sent()) {
            setcookie(self::COOKIE_NAME, $token, [
                'expires' => $expiresAt,
                'path' => '/',
                'secure' => self::isHttps(),
                'httponly' => true,
                'samesite' => $samesite,
            ]);
        }

        $_COOKIE[self::COOKIE_NAME] = $token;
    }

    private static function clearCookie(): void
    {
        if (!headers_sent()) {
            setcookie(self::COOKIE_NAME, '', [
                'expires' => time() - 3600,
                'path' => '/',
                'secure' => self::isHttps(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }
        unset($_COOKIE[self::COOKIE_NAME]);
    }

    private static function isHttps(): bool
    {
        $proto = strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
        if ($proto === 'https') {
            return true;
        }
        $https = strtolower((string)($_SERVER['HTTPS'] ?? ''));
        if ($https !== '' && $https !== 'off') {
            return true;
        }
        return isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443;
    }

    private static function cacheKey(string $token): string
    {
        return 'blackcat:sessions:user:' . $token;
    }

    private static function cacheGetUserId(string $token): ?int
    {
        if (self::$cache === null || self::$cacheTtlSeconds <= 0) {
            return null;
        }
        try {
            $v = self::$cache->get(self::cacheKey($token));
        } catch (\Throwable) {
            return null;
        }
        return is_int($v) ? $v : null;
    }

    private static function cachePutUserId(string $token, int $userId, int $expiresAt): void
    {
        if (self::$cache === null || self::$cacheTtlSeconds <= 0) {
            return;
        }

        $ttl = self::$cacheTtlSeconds;
        $remaining = $expiresAt - time();
        if ($remaining > 0) {
            $ttl = min($ttl, $remaining);
        }

        if ($ttl <= 0) {
            return;
        }

        try {
            self::$cache->set(self::cacheKey($token), $userId, $ttl);
        } catch (\Throwable) {
        }
    }

    private static function cacheDelete(string $token): void
    {
        if (self::$cache === null) {
            return;
        }
        try {
            self::$cache->delete(self::cacheKey($token));
        } catch (\Throwable) {
        }
    }
}

