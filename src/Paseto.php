<?php

/*
 * PHP Unison Fiber Framework
 * https://github.com/php-puff/paseto
 * https://github.com/php-puff/paseto/issues
 * Copyright (c) Puff
 */

declare(strict_types=1);

namespace Puff\Paseto;

use DateInterval;
use DateTimeImmutable;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Keys\Version3\AsymmetricPublicKey as Version3AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version3\AsymmetricSecretKey as Version3AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey as Version4AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey as Version4AsymmetricSecretKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Rules\IssuedBy;
use ParagonIE\Paseto\Rules\ValidAt;
use Puff\Paseto\Exception\InvalidToken;

/**
 * Signs and verifies access tokens without exposing cryptographic primitives.
 *
 * The package delegates all PASETO encoding and verification to paragonie/paseto.
 * This class only fixes the protocol version, purpose and application claim policy.
 */
final class Paseto
{
    private object $sendingKey;
    private object $receivingKey;
    private object $version;
    private Purpose $purpose;

    public function __construct(
        int $version = 4,
        string $purpose = 'local',
        #[\SensitiveParameter] string $key = '',
        #[\SensitiveParameter] string $secretKey = '',
        string $publicKey = '',
        private readonly int $ttl = 3600,
        private readonly string $issuer = '',
        private readonly string $audience = '',
    ) {
        if ($ttl < 1) {
            throw new \InvalidArgumentException('PASETO TTL must be positive.');
        }

        $this->version = match ($version) {
            3 => new Version3(),
            4 => new Version4(),
            default => throw new \InvalidArgumentException('PASETO supports versions 3 and 4.'),
        };
        $this->purpose = match ($purpose) {
            'local' => Purpose::local(),
            'public' => Purpose::public(),
            default => throw new \InvalidArgumentException('PASETO purpose must be local or public.'),
        };
        [$this->sendingKey, $this->receivingKey] = $this->keys($key, $secretKey, $publicKey);
    }

    /** @param array<string, mixed> $claims */
    public function issue(string $subject, array $claims = [], ?int $ttl = null): string
    {
        if ($subject === '') {
            throw new \InvalidArgumentException('PASETO subject cannot be empty.');
        }
        $ttl ??= $this->ttl;
        if ($ttl < 1) {
            throw new \InvalidArgumentException('PASETO TTL must be positive.');
        }

        $claims = \array_replace($claims, ['sub' => $subject]);
        if ($this->issuer !== '') {
            $claims['iss'] = $this->issuer;
        }
        if ($this->audience !== '') {
            $claims['aud'] = $this->audience;
        }

        return (new Builder())
            ->setKey($this->sendingKey)
            ->setVersion($this->version)
            ->setPurpose($this->purpose)
            ->setIssuedAt()
            ->setNotBefore()
            ->setExpiration((new DateTimeImmutable())->add(new DateInterval('PT' . $ttl . 'S')))
            ->setClaims($claims)
            ->toString();
    }

    public function ttl(): int
    {
        return $this->ttl;
    }

    /** @return array<string, mixed> */
    public function verify(#[\SensitiveParameter] string $token): array
    {
        if (\strlen($token) > 8192 || \preg_match('/^v[34]\.(?:local|public)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/D', $token) !== 1) {
            throw new InvalidToken('Invalid access token.');
        }

        try {
            $parser = (new Parser())
                ->setKey($this->receivingKey)
                ->setPurpose($this->purpose)
                ->setAllowedVersions($this->versions())
                ->addRule(new ValidAt());
            if ($this->issuer !== '') {
                $parser->addRule(new IssuedBy($this->issuer));
            }
            $claims = $parser->parse($token)->getClaims();
        } catch (PasetoException | \TypeError $exception) {
            throw new InvalidToken('Invalid access token.', 0, $exception);
        }

        if (!\is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new InvalidToken('Invalid access token subject.');
        }
        if ($this->audience !== '' && ($claims['aud'] ?? null) !== $this->audience) {
            throw new InvalidToken('Invalid access token audience.');
        }

        return $claims;
    }

    /** @return array{object, object} */
    private function keys(string $key, string $secretKey, string $publicKey): array
    {
        if ($this->purpose->equals(Purpose::local())) {
            $raw = self::decode($key);
            if (\strlen($raw) !== 32) {
                throw new \InvalidArgumentException('PASETO local key must decode to 32 bytes.');
            }
            $symmetric = new SymmetricKey($raw);
            return [$symmetric, $symmetric];
        }
        if ($secretKey === '' || $publicKey === '') {
            throw new \InvalidArgumentException('PASETO public purpose requires secret_key and public_key.');
        }
        return $this->version instanceof Version3
            ? [
                Version3AsymmetricSecretKey::fromEncodedString($secretKey),
                Version3AsymmetricPublicKey::fromEncodedString($publicKey),
            ]
            : [
                Version4AsymmetricSecretKey::fromEncodedString($secretKey),
                Version4AsymmetricPublicKey::fromEncodedString($publicKey),
            ];
    }

    private function versions(): ProtocolCollection
    {
        return $this->version instanceof Version3 ? ProtocolCollection::v3() : ProtocolCollection::v4();
    }

    /** Decodes configuration input without permitting raw key material in config files. */
    private static function decode(#[\SensitiveParameter] string $key): string
    {
        $key = \strtr($key, '-_', '+/');
        $key .= \str_repeat('=', (4 - \strlen($key) % 4) % 4);
        $decoded = \base64_decode($key, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('PASETO local key must be base64 encoded.');
        }
        return $decoded;
    }
}
