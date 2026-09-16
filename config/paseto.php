<?php

/*
 * PHP Unison Fiber Framework
 * https://github.com/php-puff/paseto
 * https://github.com/php-puff/paseto/issues
 * Copyright (c) Puff
 */

declare(strict_types=1);

return [
    'version' => 4,
    'purpose' => 'local', //local / public
    'key' => '', // Base64/base64url encoded 32-byte key for local tokens.

    'secret_key' => '', // Encoded PASETO secret key for public tokens.
    'public_key' => '', // Encoded PASETO public key for public tokens.
    
    'ttl' => 3600,
    'issuer' => '',
    'audience' => '',
];
