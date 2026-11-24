<?php

namespace OAuth2\Interfaces;

use SmartFactory\Interfaces\IInitable;

/**
 * Defines authenticated token issuance, verification and session revocation.
 *
 * @author Oleg Schildt
 */
interface IOAuthManager extends IInitable
{
    /**
     * Configures signing, verification, lifetimes and optional collaborators.
     * Each call replaces all settings. Failed initialization preserves the previous configuration.
     *
     * @param array<string, mixed> $parameters
     * Supported keys are encryption_algorithm (HS256/384/512 or RS256/384/512), secret_key (raw HMAC
     * bytes), public_key/private_key (local PEM paths), pass_phrase (private-key password),
     * access_token_ttl_minutes (integer or decimal integer string, 1..525600, default 10),
     * refresh_token_ttl_days (same format, 1..3650, default 14), token_storage (ITokenStorage),
     * user_authenticator (IUserAuthenticator), issuer (nonempty string), audience (string or nonempty
     * list of strings), key_id (nonempty string), and verification_keys (map of IDs to
     * encryption_algorithm and secret_key or public_key). Collaborators are optional for offline
     * verification; RSA verification needs no private key. Issuer and audience restrictions are
     * enforced when configured; production callers should configure both.
     *
     * @return void
     * Publishes validated settings and parsed keys together.
     *
     * @throws \OAuth2\AuthSystemException
     * If an unknown or invalid parameter is supplied, a key cannot be loaded, its type or strength is
     * invalid, its public and private parts do not match, or the same key is assigned to
     * different algorithms.
     *
     * @author Oleg Schildt
     */
    public function init(array $parameters): void;

    /**
     * Authenticates credentials and creates a new session for the supplied client.
     *
     * @param array<string, mixed> $credentials
     * Authenticator-specific credentials and a nonempty string client_id.
     *
     * @param array<string, mixed> &$response
     * Receives user_id, client_id, access_token (JWT), jwt_access_token (alias), token_type,
     * expires_in, access_token_expire, refresh_token and refresh_token_expire. Remains unchanged
     * on failure.
     *
     * @return void
     * Publishes tokens only after authentication and successful persistence.
     *
     * @throws \OAuth2\MissingParametersException
     * If client_id or an authenticator-required credential is missing.
     *
     * @throws \OAuth2\InvalidCredentialsException
     * If the authenticator rejects credentials or client_id has an invalid type.
     *
     * @throws \OAuth2\InvalidTokenException
     * If the client or returned user identifier is invalid.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration, the authenticator, signing or storage is unavailable.
     *
     * @throws \Exception
     * If the authenticator identity backend or storage fails.
     *
     * @author Oleg Schildt
     */
    public function authenticateUser(array $credentials, array &$response): void;

    /**
     * Atomically consumes a refresh token and replaces its session tokens.
     *
     * @param ?string $refresh_token
     * The current refresh token.
     *
     * @param ?string $user_id
     * The user identifier bound to the token.
     *
     * @param ?string $client_id
     * The client identifier bound to the token.
     *
     * @param array<string, mixed> &$response
     * Receives the committed response and remains unchanged on failure.
     *
     * @return void
     * Rotates the token once. Reuse revokes its matching active token family.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function refreshTokens(?string $refresh_token, ?string $user_id, ?string $client_id, array &$response): void;

    /**
     * Verifies JWT encoding, signature, claims and optionally its stored session.
     *
     * @param ?string $jwt_access_token
     * The signed access JWT.
     *
     * @param bool $check_on_server
     * Whether to enforce server-side revocation. Offline verification cannot observe logout or
     * refresh-token reuse immediately.
     *
     * @return array<string, mixed>
     * Returns validated claims; failures throw and never return false.
     *
     * @throws \OAuth2\MissingParametersException
     * If the JWT is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If encoding, signature, claims or the stored session are invalid.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the JWT or stored access token has reached its expiration time.
     *
     * @throws \OAuth2\AuthSystemException
     * If initialization or a required cryptographic or storage service fails.
     *
     * @throws \Exception
     * If storage cannot check the session.
     *
     * @author Oleg Schildt
     */
    public function verifyJwtAccessToken(?string $jwt_access_token, bool $check_on_server = true): array;

    /**
     * Checks a refresh token without extending its expiry or rotating it.
     *
     * @param ?string $refresh_token
     * The current refresh token.
     *
     * @param ?string $user_id
     * The user identifier bound to it.
     *
     * @param ?string $client_id
     * The client identifier bound to it.
     *
     * @return void
     * Returns for a matching unexpired token; detected reuse revokes its family.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function verifyRefreshToken(?string $refresh_token, ?string $user_id, ?string $client_id): void;

    /**
     * Atomically authorizes revocation using a current refresh token.
     *
     * @param ?string $user_id
     * The user owning the sessions.
     *
     * @param ?string $client_id
     * The client used to authorize the operation.
     *
     * @param ?string $refresh_token
     * A current refresh token bound to this exact user/client pair.
     *
     * @return void
     * Revokes all sessions of this user.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function invalidateUser(?string $user_id, ?string $client_id, ?string $refresh_token): void;

    /**
     * Atomically authorizes revocation using a current refresh token.
     *
     * @param ?string $user_id
     * The user owning the sessions.
     *
     * @param ?string $client_id
     * The client used to authorize the operation.
     *
     * @param ?string $refresh_token
     * A current refresh token bound to this exact user/client pair.
     *
     * @return void
     * Revokes only this user/client session; other users with the same client_id are preserved.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function invalidateClient(?string $user_id, ?string $client_id, ?string $refresh_token): void;

    /**
     * Revokes a session identified by a correctly signed JWT, including an expired JWT.
     *
     * @param ?string $jwt_access_token
     * The signed token whose opaque access ID identifies the session.
     *
     * @return void
     * Removes the matching access/refresh pair; already absent records are ignored.
     *
     * @throws \OAuth2\MissingParametersException
     * If the JWT is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If its signature, format or session claims are invalid.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration, cryptographic verification or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot persist revocation.
     *
     * @author Oleg Schildt
     */
    public function invalidateJwtAccessToken(?string $jwt_access_token): void;

    /**
     * Revokes a session by possession of a current or previously consumed refresh token.
     *
     * @param ?string $refresh_token
     * The nonempty refresh token identifying the family; it need not be unexpired.
     *
     * @return void
     * Removes its active token family. Unknown tokens are ignored for idempotent revocation.
     *
     * @throws \OAuth2\MissingParametersException
     * If the refresh token is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If the token contains invalid characters or exceeds the size limit.
     *
     * @throws \OAuth2\AuthSystemException
     * If configuration or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot persist revocation.
     *
     * @author Oleg Schildt
     */
    public function invalidateRefreshToken(?string $refresh_token): void;
} // IOAuthManager
