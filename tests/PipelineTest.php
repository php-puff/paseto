<?php

/*
 * PHP Unison Fiber Framework
 * https://github.com/php-puff/paseto
 * https://github.com/php-puff/paseto/issues
 * Copyright (c) Puff
 */

declare(strict_types=1);

namespace Puff\Paseto\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Puff\Http\Request;
use Puff\Http\Response;
use Puff\Paseto\Paseto;
use Puff\Paseto\Pipeline;

final class PipelineTest extends TestCase
{
    public function testAttachesVerifiedClaims(): void
    {
        $key = \rtrim(\strtr(\base64_encode(\random_bytes(32)), '+/', '-_'), '=');
        $paseto = new Paseto(key: $key);
        $token = $paseto->issue('user-42');
        $pipeline = new Pipeline($paseto);

        $response = $pipeline->handle(
            new Request(headers: ['Authorization' => 'Bearer ' . $token]),
            function (ServerRequestInterface $request): Response {
                self::assertSame('user-42', $request->getAttribute('paseto')['sub']);
                return new Response();
            },
        );

        self::assertSame(200, $response->getStatusCode());
    }

    public function testRejectsMissingCredentials(): void
    {
        $key = \rtrim(\strtr(\base64_encode(\random_bytes(32)), '+/', '-_'), '=');
        $response = (new Pipeline(new Paseto(key: $key)))->handle(new Request(), static fn (): Response => new Response());

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }
}
