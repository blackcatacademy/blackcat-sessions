<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Tests\Unit;

use BlackCat\Sessions\Php\PhpSessionCodec;
use PHPUnit\Framework\TestCase;

final class PhpSessionCodecTest extends TestCase
{
    public function testEncodeDecodeRoundTrip(): void
    {
        $data = [
            'user_id' => 123,
            'roles' => ['customer', 'admin'],
            'flag' => false,
            'nested' => ['x' => 1, 'y' => null],
        ];

        $payload = PhpSessionCodec::encode($data);
        $decoded = PhpSessionCodec::decode($payload);

        self::assertSame($data, $decoded);
    }

    public function testDecodeInvalidReturnsNull(): void
    {
        self::assertNull(PhpSessionCodec::decode('foo|'));
    }

    public function testSanitizeDropsObjectsAndResources(): void
    {
        $res = fopen('php://memory', 'rb');
        self::assertIsResource($res);

        $data = [
            'ok' => 1,
            'obj' => (object)['x' => 1],
            'res' => $res,
            'nested' => [
                'obj2' => new \stdClass(),
                'ok2' => 'a',
            ],
        ];

        $sanitized = PhpSessionCodec::sanitize($data);

        self::assertSame(['ok' => 1, 'nested' => ['ok2' => 'a']], $sanitized);

        fclose($res);
    }
}

