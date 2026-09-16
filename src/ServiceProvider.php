<?php

/*
 * PHP Unison Fiber Framework
 * https://github.com/php-puff/paseto
 * https://github.com/php-puff/paseto/issues
 * Copyright (c) Puff
 */

declare(strict_types=1);

namespace Puff\Paseto;

use Puff\Config\Config;
use Puff\Di\ServiceProvider as BaseServiceProvider;

/** Registers one immutable PASETO service from application configuration. */
final class ServiceProvider extends BaseServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Paseto::class, function (): Paseto {
            $config = $this->app->get(Config::class);
            return new Paseto((int) $config->get('paseto.version', 4), (string) $config->get('paseto.purpose', 'local'), (string) $config->get('paseto.key', ''), (string) $config->get('paseto.secret_key', ''), (string) $config->get('paseto.public_key', ''), (int) $config->get('paseto.ttl', 3600), (string) $config->get('paseto.issuer', ''), (string) $config->get('paseto.audience', ''));
        });
    }
}
