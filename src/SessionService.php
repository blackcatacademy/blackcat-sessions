<?php
declare(strict_types=1);

namespace BlackCat\Sessions;

use BlackCat\Sessions\Store\SessionStoreInterface;

final class SessionService
{
    public function __construct(
        private readonly SessionStoreInterface $store,
        private readonly int $ttl = 1209600, // 14 days
    ) {}

    /**
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $context
     */
    public function issue(array $claims, array $context = []): SessionRecord
    {
        $subject = (string)($claims['sub'] ?? '');
        if ($subject === '') {
            throw new \RuntimeException('session_missing_subject');
        }
        $session = SessionRecord::issue($subject, $claims, $context, $this->ttl);
        $this->store->save($session);
        return $session;
    }

    public function validate(string $sessionId): ?SessionRecord
    {
        $session = $this->store->find($sessionId);
        if ($session === null || $session->isExpired()) {
            return null;
        }
        return $session;
    }

    public function revoke(string $sessionId): void
    {
        $this->store->revoke($sessionId);
    }

    /**
     * @return list<SessionRecord>
     */
    public function sessionsFor(string $subject): array
    {
        return $this->store->findBySubject($subject);
    }
}

