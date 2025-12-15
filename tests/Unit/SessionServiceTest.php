<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Tests\Unit;

use BlackCat\Sessions\SessionService;
use BlackCat\Sessions\Store\InMemorySessionStore;
use PHPUnit\Framework\TestCase;

final class SessionServiceTest extends TestCase
{
    public function testIssueAndValidateInMemory(): void
    {
        $store = new InMemorySessionStore();
        $svc = new SessionService($store, ttl: 2);

        $record = $svc->issue(['sub' => 'u1', 'roles' => ['customer']], ['ip' => '127.0.0.1']);
        self::assertSame('u1', $record->subject);
        self::assertNotSame('', $record->id);

        $validated = $svc->validate($record->id);
        self::assertNotNull($validated);
        self::assertSame($record->id, $validated->id);
    }
}

