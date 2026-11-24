## SmartFactory OAuth2 Server

- Lightweight simple and flexible OAuth2 Server
- With support of the JSON Web Token
- Customizable user authentication and storage of the token records
- Designed based on IoC 

For more details see [Presentation](http://php-smart-factory.org/oauth2_presentation.pdf) and
[OAuth2 API documentation](http://php-smart-factory.org/oauth2/).

### Requirements

- PHP 8.5+

### Installation

```
composer require "smartfactory/oauth2"
```

**composer.json**
 
```
{
  ...

  "require": {
    "php": ">=8.5",
    "smartfactory/smartfactory": ">=2.2.0",
    "smartfactory/oauth2": ">=2.2.0"
  }
  
  ...
}
```

### To get familiar with the SmartFactory Core and OAuth2 Server do the following:

- Git-clone the demo application [SmartFactoryDemo](https://github.com/oschildt/SmartFactoryDemo) and run 'composer update'.
- Use the script *database/create_database_mysql.sql* (*create_database_mssql.sql*) to create a demo database necessary for some examples.
- View and study the API documentation in the folder docs or here [OAuth2 API documentation](http://php-smart-factory.org/oauth2/).
- Study the core code of the library SmartFactory and SmartFactory OAuth2 Server.
- The example *application/17.oauth.php* demonstrates the token manager.

### To start writing own application using SmartFactory OAuth2 Server

1. Git-clone the demo application [SmartFactoryDemo](https://github.com/oschildt/SmartFactoryDemo) and run 'composer update'.

2. Study the directory structure of the demo application and the code.

3. Implement the interfaces IUserAuthenticator and ITokenStorage.

4. Bind your classes to the interfaces in *initialization_inc.php* to use the IoC object factory.

5. Implement the JSON API request handlers.

6. Add application translations through *localization/edit.php* or directly in *localization/texts.json*. Use *localization/check.php* to check for missing translations.

## Token configuration and security contract

This package supplies a token-service core. The calling application supplies HTTPS
endpoints, request throttling, client registration and authorization policy. An OAuth
authorization-code flow with PKCE, scopes, consent and confidential-client authentication
must be implemented by that application or a dedicated authorization server. Direct
password authentication is provided for the first-party demo; it must not be exposed
as the deprecated OAuth resource-owner password grant to third-party clients.

```php
$manager->init([
    'encryption_algorithm' => 'RS256',
    'public_key' => '/secure/oauth/public.pem',
    'private_key' => '/secure/oauth/private.pem',
    'token_storage' => $storage,
    'user_authenticator' => $authenticator,
    'access_token_ttl_minutes' => 10,
    'refresh_token_ttl_days' => 14,
    'issuer' => 'https://auth.example.com',
    'audience' => 'https://api.example.com',
    'key_id' => 'rsa-2026-11',
]);
```

- Configure issuer and audience consistently on issuers and resource servers. If omitted,
  these restrictions are disabled; this is suitable only for an isolated single-service use.
- RSA keys must be RSA keys of at least 2048 bits and the supplied pair must match.
  HMAC needs only `secret_key`: use cryptographically random raw bytes of at least
  32, 48 or 64 bytes for HS256, HS384 or HS512, respectively. Length validation cannot
  establish entropy; never use a memorable password as the signing secret.
- `init()` replaces configuration atomically. Unknown parameters are rejected.
  TTL values are integers or decimal integer strings; access TTL is 1..525600 minutes
  and refresh TTL is 1..3650 days. Defaults are 10 minutes and 14 days.
- Token verification checks canonical unpadded Base64URL, object-shaped UTF-8 JSON,
  the configured algorithm and key, and typed, consistent `sub`, `jti`, `iat`, `exp`
  and session claims. Unsupported critical header extensions are rejected.
- Lifetimes are fixed. Checking either token updates activity without extending validity.
  Refreshing issues a new pair with new lifetimes. A token is expired at its expiration second.
- Authentication responses contain `access_token` (the JWT), `token_type` (`Bearer`),
  `expires_in` (seconds), `refresh_token`, absolute expiration timestamps, `user_id`
  and `client_id`. `jwt_access_token` remains an alias for the same JWT.
  The opaque access ID inside the JWT is an internal session identifier.
- Responses are replaced only after storage commits. They remain unchanged on failure;
  callers must return tokens only after successful completion, never from a catch branch.
- `verifyJwtAccessToken()` returns claims or throws; it never returns `false`.
  Its default storage check enforces revocation. Passing `false` permits offline
  verification and therefore accepts revoked tokens until their signed expiration.
- A verifier may configure only `encryption_algorithm`, `public_key`, issuer, audience
  and key ID. Neither a private key nor storage nor an authenticator is required
  for offline RSA verification. HMAC verifiers necessarily possess signing material.

### Key rollover

Set `key_id` for the active key and retain trusted previous public keys in
`verification_keys`. Each entry contains its own fixed `encryption_algorithm` and
`public_key` (or `secret_key` for HMAC). The same key material cannot be bound to
different algorithms. IDs select local configuration only; JWT URLs are never fetched.

```php
'key_id' => 'rsa-2026-11',
'verification_keys' => [
    'rsa-2026-10' => [
        'encryption_algorithm' => 'RS256',
        'public_key' => '/secure/oauth/previous-public.pem',
    ],
],
```

When an active key ID is configured, tokens without `kid` are rejected. Unknown IDs
are always rejected. Keep previous verification keys until their tokens expire;
remove compromised keys immediately.

### Storage migration and refresh-token rotation

Custom `ITokenStorage` implementations must add `rotateTokenRecord()` and
`revokeTokenRecords()`. Rotation must check binding and expiry, consume the previous
token, retain its hash and replace the record in one transaction or lock. A separate
verify followed by save is unsafe. Retain consumed refresh hashes until their original
expiration and revoke the matching active family when reuse is detected. Concurrent
reuse may therefore invalidate the winning response too; clients must serialize refresh
requests and authenticate again after a replay rejection. Fresh authentication starts
a new family and cannot be revoked by replay of an older family's token.

Exactly one active session per `user_id`/`client_id` pair is allowed. Client logout is
scoped to that pair; user logout affects all of that user's sessions. The low-level
`deleteTokenRecordByKey('client_id', ...)` operation is global and must be restricted
to administrative callers. Possession-based access/refresh revocation is idempotent.

`DemoTokenStorage` uses a stable `.lock` file and atomically replaces complete XML
snapshots. All processes accessing the same file must use this implementation's locking
protocol. The directory must exist and be writable; do not expose it through the web
server. Store only SHA-256 token hashes, never raw tokens or JWTs. Corrupted, empty,
oversized or unsupported XML is rejected without clearing the existing file.
The example limits snapshots to 16 MiB; use a transactional database for production scale.

Legacy `<array>` XML is validated and migrated under the lock on first access, including
an empty `<array/>`. Existing refresh tokens can be used to obtain the new JWT format;
old JWTs without standard session claims require refreshing or signing in again.
Migration removes recoverable tokens from the active XML; manage old backups separately.
The migration and version-2 writer preserve fixed stored expirations.

### Authentication and exceptions

`IUserAuthenticator::authenticateUser()` returns `int|string` and throws on failure.
Existing implementations returning only `int` remain compatible. String IDs, including
`"0"`, are supported. Credential and identifier types are validated without implicit
array or boolean conversion.

`DemoUserAuthenticator` retains the demonstration account `john` / `qwerty` with ID 129.
It uses `password_verify()` and accepts an optional `users` map of login to
`['user_id' => ..., 'password_hash' => ...]`. Configure hashes created with
`password_hash()`; an empty map disables all accounts. This in-memory identity store
is an example, not a production user database.

All five OAuth exception constructors accept an optional final `previous` throwable.
Defaults distinguish `system_error`, `invalid_token`, `invalid_credentials`,
`missing_request_data` and `token_expired`. Internal file paths and OpenSSL diagnostics
are not included in public token-manager error messages.

## Directory Structure 

```
docs
src
  OAuth2
    Interfaces
```

## Detailed description

### docs
This directory contains the documentation about classes, interfaces and functions of the SmartFactory OAuth2 Server.

### src
This is the root directory for all classes and interfaces. The class loader is implemented based on PSR4 approach. You have no need to add additional class loader function.

### src/OAuth2
This directory contains the core classes and interfaces of the SmartFactory OAuth2 Server.

### src/OAuth2/Interfaces
This directory contains the core interfaces of the SmartFactory OAuth2 Server.

