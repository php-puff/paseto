# Puff PASETO

`puff/paseto` adds PASETO v3/v4 authentication to Puff through the audited `paragonie/paseto` implementation. It supports `local` encrypted tokens and `public` signed tokens; v4 `local` is the default.

```bash
composer require puff/paseto
```

Set a base64url-encoded 32-byte `paseto.key` in the published `config/paseto.php`, then issue and verify tokens:

```php
$token = $paseto->issue('user-42', ['role' => 'admin']);
$claims = $paseto->verify($token);
```

Add `Puff\Paseto\Pipeline::class` to an HTTP pipeline. It accepts an `Authorization: Bearer <token>` header and exposes verified claims as the request attribute `paseto`. Invalid or missing tokens return a `401` response with `Cache-Control: no-store`.

For `purpose: public`, configure encoded PASETO `secret_key` and `public_key`. Do not use raw keys in source control.
