<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Store;

use BlackCat\Sessions\SessionRecord;

final class RedisSessionStore implements SessionStoreInterface
{
    public function __construct(
        private readonly \Redis $redis,
        private readonly string $prefix = 'blackcat:sessions'
    ) {}

    public function save(SessionRecord $session): void
    {
        $data = [
            'subject' => $session->subject,
            'issued_at' => $session->issuedAt,
            'expires_at' => $session->expiresAt,
            'claims' => json_encode($session->claims),
            'context' => json_encode($session->context),
        ];
        $ttl = max(1, $session->expiresAt - time());
        $this->redis->setex($this->key($session->id), $ttl, json_encode($data));
        $this->redis->sAdd($this->subjectKey($session->subject), $session->id);
        $this->redis->expire($this->subjectKey($session->subject), $ttl);
    }

    public function find(string $sessionId): ?SessionRecord
    {
        $raw = $this->redis->get($this->key($sessionId));
        if ($raw === false || $raw === null) {
            return null;
        }
        $json = json_decode($raw, true);
        if (!is_array($json)) {
            return null;
        }
        return new SessionRecord(
            $sessionId,
            (string)$json['subject'],
            (int)$json['issued_at'],
            (int)$json['expires_at'],
            json_decode((string)$json['claims'], true) ?: [],
            json_decode((string)$json['context'], true) ?: []
        );
    }

    public function revoke(string $sessionId): void
    {
        $session = $this->find($sessionId);
        if ($session) {
            $this->redis->sRem($this->subjectKey($session->subject), $sessionId);
        }
        $this->redis->del($this->key($sessionId));
    }

    public function findBySubject(string $subject): array
    {
        $ids = $this->redis->sMembers($this->subjectKey($subject));
        if (!is_array($ids)) {
            $ids = [];
        }
        $sessions = [];
        foreach ($ids as $id) {
            $record = $this->find((string)$id);
            if ($record !== null && !$record->isExpired()) {
                $sessions[] = $record;
            }
        }
        return $sessions;
    }

    private function key(string $sessionId): string
    {
        return $this->prefix . ':' . $sessionId;
    }

    private function subjectKey(string $subject): string
    {
        return $this->prefix . ':subject:' . $subject;
    }
}
