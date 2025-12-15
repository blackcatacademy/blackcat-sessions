<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Store;

use BlackCat\Sessions\SessionRecord;

final class InMemorySessionStore implements SessionStoreInterface
{
    /** @var array<string,SessionRecord> */
    private array $sessions = [];

    public function save(SessionRecord $session): void
    {
        $this->sessions[$session->id] = $session;
    }

    public function find(string $sessionId): ?SessionRecord
    {
        return $this->sessions[$sessionId] ?? null;
    }

    public function revoke(string $sessionId): void
    {
        unset($this->sessions[$sessionId]);
    }

    public function findBySubject(string $subject): array
    {
        return array_values(array_filter(
            $this->sessions,
            static fn(SessionRecord $record) => $record->subject === $subject && !$record->isExpired()
        ));
    }
}

