<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Store;

use BlackCat\Core\Database;
use BlackCat\Database\Crypto\IngressLocator;
use BlackCat\Database\Packages\Sessions\Criteria as SessionsCriteria;
use BlackCat\Database\Packages\Sessions\Repository\SessionRepository;
use BlackCat\Database\Support\BinaryCodec;
use BlackCat\Sessions\SessionRecord;

final class DatabaseSessionStore implements SessionStoreInterface
{
    private SessionRepository $sessions;

    public function __construct(
        private readonly Database $db,
        ?SessionRepository $sessions = null,
    ) {
        $this->sessions = $sessions ?? new SessionRepository($db);
    }

    public function save(SessionRecord $session): void
    {
        $userId = ctype_digit($session->subject) ? (int)$session->subject : null;
        $fingerprint = hash('sha256', $session->id, true);

        $issuedAt = self::formatSqlDateTimeFromEpoch($session->issuedAt);
        $expiresAt = self::formatSqlDateTimeFromEpoch($session->expiresAt);

        $ip = $session->context['ip'] ?? $session->context['client_ip'] ?? null;
        $ip = is_string($ip) ? trim($ip) : null;
        if ($ip === '') {
            $ip = null;
        }

        $ua = $session->context['user_agent'] ?? $session->context['ua'] ?? null;
        $ua = is_string($ua) ? trim($ua) : null;
        if ($ua === '') {
            $ua = null;
        }

        $blob = [
            'id' => $session->id,
            'subject' => $session->subject,
            'issued_at' => $session->issuedAt,
            'expires_at' => $session->expiresAt,
            'claims' => $session->claims,
            'context' => $session->context,
        ];

        $blobJson = json_encode($blob, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($blobJson === false) {
            $blobJson = json_encode($blob, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        }
        if ($blobJson === false) {
            throw new \RuntimeException('session_blob_encode_failed');
        }

        $this->sessions->insert([
            'token_hash' => $session->id,
            'token_issued_at' => $issuedAt,
            'token_fingerprint' => $fingerprint,
            'user_id' => $userId,
            'expires_at' => $expiresAt,
            'revoked' => false,
            'ip_hash' => $ip,
            'user_agent' => $ua,
            'session_blob' => $blobJson,
        ]);
    }

    public function find(string $sessionId): ?SessionRecord
    {
        $sessionId = trim($sessionId);
        if ($sessionId === '') {
            return null;
        }

        $id = $this->resolveRowIdForToken($sessionId);
        if ($id <= 0) {
            return null;
        }

        $full = $this->sessions->findAllByIds([$id]);
        $fullRow = $full[0] ?? null;
        if (!is_array($fullRow)) {
            return null;
        }

        if (!empty($fullRow['revoked'])) {
            return null;
        }

        $record = $this->hydrateSession($fullRow, $sessionId);
        if ($record === null) {
            return null;
        }

        if ($record->isExpired()) {
            return null;
        }

        return $record;
    }

    public function revoke(string $sessionId): void
    {
        $sessionId = trim($sessionId);
        if ($sessionId === '') {
            return;
        }

        $id = $this->resolveRowIdForToken($sessionId);
        if ($id <= 0) {
            return;
        }

        $this->sessions->updateById($id, ['revoked' => true]);
    }

    public function findBySubject(string $subject): array
    {
        $subject = trim($subject);
        if ($subject === '' || !ctype_digit($subject)) {
            return [];
        }
        $userId = (int)$subject;
        if ($userId <= 0) {
            return [];
        }

        $crit = SessionsCriteria::fromDb($this->db)
            ->where('user_id', '=', $userId)
            ->orderBy('created_at', 'DESC')
            ->setPerPage(500)
            ->setPage(1);

        $page = $this->sessions->paginate($crit);
        $items = is_array($page['items'] ?? null) ? $page['items'] : [];
        if ($items === []) {
            return [];
        }

        $ids = [];
        foreach ($items as $row) {
            if (!is_array($row) || !isset($row['id'])) {
                continue;
            }
            $id = (int)$row['id'];
            if ($id > 0) {
                $ids[] = $id;
            }
        }
        if ($ids === []) {
            return [];
        }

        $rows = $this->sessions->findAllByIds($ids);
        if ($rows === []) {
            return [];
        }

        $byId = [];
        foreach ($rows as $r) {
            if (is_array($r) && isset($r['id'])) {
                $byId[(int)$r['id']] = $r;
            }
        }

        $out = [];
        foreach ($ids as $id) {
            $r = $byId[$id] ?? null;
            if (!is_array($r) || !empty($r['revoked'])) {
                continue;
            }
            $record = $this->hydrateSession($r, null);
            if ($record !== null && !$record->isExpired()) {
                $out[] = $record;
            }
        }
        return $out;
    }

    /**
     * @param array<string,mixed> $row Base-table row.
     */
    private function hydrateSession(array $row, ?string $fallbackToken): ?SessionRecord
    {
        $blob = $this->decodeSessionBlob($row['session_blob'] ?? null);
        if ($blob === null) {
            return null;
        }

        $token = $fallbackToken ?? (is_string($blob['id'] ?? null) ? (string)$blob['id'] : null);
        $token = is_string($token) ? trim($token) : null;
        if ($token === null || $token === '') {
            return null;
        }

        $subject = is_string($blob['subject'] ?? null) ? (string)$blob['subject'] : (string)($row['user_id'] ?? '');
        $subject = trim($subject);

        $issuedAt = isset($blob['issued_at']) ? (int)$blob['issued_at'] : self::parseSqlDateTimeToEpoch($row['token_issued_at'] ?? null);
        $expiresAt = isset($blob['expires_at']) ? (int)$blob['expires_at'] : self::parseSqlDateTimeToEpoch($row['expires_at'] ?? null);

        $claims = is_array($blob['claims'] ?? null) ? (array)$blob['claims'] : [];
        $context = is_array($blob['context'] ?? null) ? (array)$blob['context'] : [];

        if ($issuedAt <= 0) {
            $issuedAt = time();
        }
        if ($expiresAt <= 0) {
            $expiresAt = $issuedAt;
        }

        return new SessionRecord($token, $subject, $issuedAt, $expiresAt, $claims, $context);
    }

    /**
     * @return array<string,mixed>|null
     */
    private function decodeSessionBlob(mixed $raw): ?array
    {
        if ($raw === null || $raw === '') {
            return null;
        }

        $blob = BinaryCodec::toBinary($raw);
        if (!is_string($blob) || $blob === '') {
            return null;
        }

        // Best-effort decrypt when crypto ingress is available.
        try {
            $adapter = IngressLocator::adapter();
        } catch (\Throwable) {
            $adapter = null;
        }
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

        $data = json_decode($blob, true);
        return is_array($data) ? $data : null;
    }

    private function resolveRowIdForToken(string $token): int
    {
        $token = trim($token);
        if ($token === '') {
            return 0;
        }

        // Fast path: HMAC-backed unique key lookup (works while the active key stays stable).
        $row = $this->sessions->getByTokenHash($token, false);
        if (is_array($row) && isset($row['id'])) {
            $id = (int)$row['id'];
            if ($id > 0) {
                return $id;
            }
        }

        // Fallback: fingerprint lookup (supports key rotation without breaking existing sessions).
        $fingerprint = hash('sha256', $token, true);
        $crit = SessionsCriteria::fromDb($this->db)
            ->where('token_fingerprint', '=', $fingerprint)
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

    private static function parseSqlDateTimeToEpoch(mixed $value): int
    {
        if (!is_string($value) || trim($value) === '') {
            return 0;
        }
        try {
            $dt = new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
            return $dt->getTimestamp();
        } catch (\Throwable) {
            return 0;
        }
    }

    private static function formatSqlDateTimeFromEpoch(int $epochSec): string
    {
        $epochSec = max(0, $epochSec);
        $dt = (new \DateTimeImmutable('@' . $epochSec))->setTimezone(new \DateTimeZone('UTC'));
        return $dt->format('Y-m-d H:i:s.u');
    }
}
