<?php

/*
 * PHP Unison Fiber Framework
 * https://github.com/php-puff/paseto
 * https://github.com/php-puff/paseto/issues
 * Copyright (c) Puff
 */

declare(strict_types=1);

namespace Puff\Paseto;

use Closure;
use Psr\Http\Message\ServerRequestInterface;
use Puff\Http\Response;
use Puff\Paseto\Exception\InvalidToken;

/** Verifies Bearer PASETO credentials and attaches claims as `paseto`. */
final readonly class Pipeline
{
    public function __construct(private Paseto $paseto) {}

    public function handle(ServerRequestInterface $request, Closure $next): mixed
    {
        if (\preg_match('/^Bearer\s+(.+)$/iD', $request->getHeaderLine('Authorization'), $match) !== 1) return $this->unauthorized(false);
        try {$claims = $this->paseto->verify($match[1]);} catch (InvalidToken) {return $this->unauthorized(true);}
        return $next($request->withAttribute('paseto', $claims));
    }

    private function unauthorized(bool $invalid): Response
    {
        return (new Response())->json(['error' => 'unauthorized'], 401)->withHeader('WWW-Authenticate', $invalid ? 'Bearer error="invalid_token"' : 'Bearer')->withHeader('Cache-Control', 'no-store');
    }
}
