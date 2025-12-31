<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Php;

/**
 * Helpers for PHP's default `session.serialize_handler=php` format.
 *
 * Format: key|<serialize(value)>key2|<serialize(value2)>...
 */
final class PhpSessionCodec
{
    private function __construct() {}

    /**
     * Parse `serialize_handler=php` payload into array.
     *
     * @return array<string,mixed>|null
     */
    public static function decode(string $payload): ?array
    {
        if ($payload === '') {
            return [];
        }

        $len = strlen($payload);
        if ($len > 1024 * 1024) {
            return null;
        }

        $offset = 0;
        $res = [];

        $maxIterations = 200000;
        $iters = 0;

        while ($offset < $len) {
            if (++$iters > $maxIterations) {
                return null;
            }

            $pipe = strpos($payload, '|', $offset);
            if ($pipe === false) {
                break;
            }

            $name = substr($payload, $offset, $pipe - $offset);
            $offset = $pipe + 1;
            if ($offset >= $len) {
                return null;
            }

            $ok = false;
            for ($i = 1; $offset + $i <= $len; $i++) {
                if (++$iters >= $maxIterations) {
                    return null;
                }

                $chunk = substr($payload, $offset, $i);
                $val = self::safeUnserialize($chunk);
                if ($val !== false || $chunk === 'b:0;') {
                    $res[$name] = $val;
                    $offset += $i;
                    $ok = true;
                    break;
                }
            }

            if (!$ok) {
                return null;
            }
        }

        return $res;
    }

    /**
     * Encode associative array into `serialize_handler=php` payload.
     *
     * @param array<string,mixed> $data
     */
    public static function encode(array $data): string
    {
        $out = '';
        foreach ($data as $key => $value) {
            $safeKey = str_replace('|', '_', (string)$key);
            $out .= $safeKey . '|' . serialize($value);
        }
        return $out;
    }

    /**
     * Basic sanitization before persistence:
     * - removes objects/resources
     * - recurses arrays
     *
     * @param array<string,mixed> $session
     * @return array<string,mixed>
     */
    public static function sanitize(array $session): array
    {
        $clean = [];
        foreach ($session as $k => $v) {
            if (is_object($v) || is_resource($v)) {
                continue;
            }
            if (is_array($v)) {
                $clean[$k] = self::sanitize($v);
                continue;
            }
            $clean[$k] = $v;
        }
        return $clean;
    }

    private static function safeUnserialize(string $data): mixed
    {
        set_error_handler(static function ($severity, $message, $file = null, $line = null): never {
            throw new \ErrorException((string)$message, 0, (int)$severity, (string)$file, (int)$line);
        });

        try {
            return unserialize($data, ['allowed_classes' => false]);
        } catch (\Throwable) {
            return false;
        } finally {
            restore_error_handler();
        }
    }
}
