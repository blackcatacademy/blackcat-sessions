<?php
declare(strict_types=1);

namespace BlackCat\Sessions;

final class SessionRecord
{
    /**
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $context
     */
    public function __construct(
        public readonly string $id,
        public readonly string $subject,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly array $claims,
        public readonly array $context = [],
    ) {}

    /**
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $context
     */
    public static function issue(string $subject, array $claims, array $context, int $ttl): self
    {
        $now = time();
        return new self(
            id: bin2hex(random_bytes(16)),
            subject: $subject,
            issuedAt: $now,
            expiresAt: $now + max(0, $ttl),
            claims: $claims,
            context: $context
        );
    }

    public function isExpired(): bool
    {
        return $this->expiresAt <= time();
    }
}

