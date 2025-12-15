<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Store;

use BlackCat\Sessions\SessionRecord;

interface SessionStoreInterface
{
    public function save(SessionRecord $session): void;

    public function find(string $sessionId): ?SessionRecord;

    public function revoke(string $sessionId): void;

    /**
     * @return list<SessionRecord>
     */
    public function findBySubject(string $subject): array;
}

