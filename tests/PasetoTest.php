<?php

/*
 * PHP Unison Fiber Framework
 * https://github.com/php-puff/paseto
 * https://github.com/php-puff/paseto/issues
 * Copyright (c) Puff
 */

declare(strict_types=1);

namespace Puff\Paseto\Tests;

use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use PHPUnit\Framework\TestCase;
use Puff\Paseto\Exception\InvalidToken;
use Puff\Paseto\Paseto;

final class PasetoTest extends TestCase
{
    public function testIssuesAndVerifiesV4LocalToken(): void
    {
        $paseto = new Paseto(key: $this->key(), issuer: 'puff', audience: 'api');

        $claims = $paseto->verify($paseto->issue('user-42', ['role' => 'admin']));

        self::assertSame('user-42', $claims['sub']);
        self::assertSame('admin', $claims['role']);
        self::assertSame('puff', $claims['iss']);
        self::assertSame('api', $claims['aud']);
    }

    public function testRejectsModifiedToken(): void
    {
        $paseto = new Paseto(key: $this->key());
        $token = $paseto->issue('user-42');
        $token[-1] = $token[-1] === 'a' ? 'b' : 'a';

        $this->expectException(InvalidToken::class);
        $paseto->verify($token);
    }

    public function testRejectsUnexpectedAudience(): void
    {
        $key = $this->key();
        $token = (new Paseto(key: $key, audience: 'admin'))->issue('user-42');

        $this->expectException(InvalidToken::class);
        (new Paseto(key: $key, audience: 'api'))->verify($token);
    }

    public function testIssuesAndVerifiesV4PublicToken(): void
    {
        $secret = new AsymmetricSecretKey(\sodium_crypto_sign_keypair());
        $paseto = new Paseto(
            purpose: 'public',
            secretKey: $secret->encode(),
            publicKey: $secret->getPublicKey()->encode(),
        );

        self::assertSame('user-42', $paseto->verify($paseto->issue('user-42'))['sub']);
    }

    public function testRejectsInvalidConfiguration(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Paseto(key: 'not-a-key');
    }

    private function key(): string
    {
        return \rtrim(\strtr(\base64_encode(\random_bytes(32)), '+/', '-_'), '=');
    }
}
