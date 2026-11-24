<?php

namespace OAuth2\Interfaces;

use SmartFactory\Interfaces\IInitable;

/**
 * Defines process-safe session persistence, refresh-token rotation and revocation.
 * All readers and writers of the same backend must participate in the same locking or transaction
 * protocol. Storage must not contain raw bearer tokens.
 *
 * @author Oleg Schildt
 */
interface ITokenStorage extends IInitable
{
    /**
     * Loads a session matching the exact user/client pair and one supplied token.
     * Implementations must use constant-time hash comparison and must never return recoverable stored
     * bearer tokens.
     *
     * @param array<string, mixed> &$token_record
     * Input: user_id, client_id and exactly one of access_token or refresh_token. Output: the matching
     * record with expiry, last_activity, family_id and token hashes; only the supplied raw lookup
     * token may remain in the array.
     *
     * @return void
     * Replaces the array only on success; missing records throw.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @author Oleg Schildt
     */
    public function loadTokenRecord(array &$token_record): void;

    /**
     * Atomically replaces the session for one user/client pair after fresh authentication.
     * Exactly one active record per pair is permitted. Replacement starts a new family, so replay of
     * an older family cannot revoke the newly authenticated session.
     *
     * @param array<string, mixed> &$token_record
     * A record containing nonempty string user_id, client_id, access_token and refresh_token, and
     * integer Unix timestamps access_token_expire, refresh_token_expire and last_activity. Raw tokens
     * are inputs only: persist SHA-256 hashes, never recoverable bearer credentials. The caller must
     * not rely on storage mutating this array.
     *
     * @return void
     * Commits the complete record or preserves the previous session on failure.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @author Oleg Schildt
     */
    public function saveTokenRecord(array &$token_record): void;

    /**
     * Atomically checks and consumes a refresh token and replaces its session.
     * The check, expiry test, consumed-token history and replacement must share one transaction or
     * lock. Reuse of a consumed token must revoke its active family before throwing. Retain consumed
     * hashes at least until their original expiration time. Never combine a separate verify operation
     * with an unconditional save.
     *
     * @param ?string $refresh_token
     * The previous refresh token to consume exactly once.
     *
     * @param array<string, mixed> &$token_record
     * A record containing nonempty string user_id, client_id, access_token and refresh_token, and
     * integer Unix timestamps access_token_expire, refresh_token_expire and last_activity. Raw tokens
     * are inputs only: persist SHA-256 hashes, never recoverable bearer credentials. The caller must
     * not rely on storage mutating this array. The user/client pair must match the previous token.
     *
     * @return void
     * Preserves the family ID and commits one replacement.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the current refresh token has reached its expiration time.
     *
     * @author Oleg Schildt
     */
    public function rotateTokenRecord(?string $refresh_token, array &$token_record): void;

    /**
     * Atomically authorizes revocation with a current refresh token and deletes sessions.
     * Authorization and deletion must share one transaction or lock. Client-scoped revocation must
     * always include user_id in its deletion predicate.
     *
     * @param ?string $refresh_token
     * The current token authorizing revocation.
     *
     * @param ?string $user_id
     * The user owning the token and sessions.
     *
     * @param ?string $client_id
     * The client bound to the authorizing token.
     *
     * @param bool $all_user_sessions
     * Whether to delete every session of this user instead of only this user/client pair.
     *
     * @return void
     * Revokes only authorized sessions and preserves all other users.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the authorizing refresh token is expired.
     *
     * @author Oleg Schildt
     */
    public function revokeTokenRecords(
        ?string $refresh_token,
        ?string $user_id,
        ?string $client_id,
        bool $all_user_sessions = false
    ): void;

    /**
     * Atomically revokes sessions by a validated key and exact value.
     * This low-level administrative operation does not authenticate the caller. Public handlers must
     * use authorized manager methods. Refresh-token lookup also recognizes retained consumed hashes
     * and revokes only their matching family.
     *
     * @param string $key
     * One of user_id, client_id, access_token or refresh_token. The client_id key is global and
     * requires administrative authorization.
     *
     * @param ?string $value
     * The nonempty exact identifier or raw token to hash and compare.
     *
     * @return void
     * Ignores absent records, making possession-based token revocation idempotent.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @author Oleg Schildt
     */
    public function deleteTokenRecordByKey(string $key, ?string $value): void;

    /**
     * Checks the exact token/user/client binding and fixed expiration under a storage lock.
     * Verification must not extend either token lifetime. Refresh-token reuse must revoke its matching
     * family before reporting failure.
     *
     * @param ?string $access_token
     * The raw token to verify.
     *
     * @param ?string $user_id
     * The user identifier bound to the token.
     *
     * @param ?string $client_id
     * The client identifier bound to the token.
     *
     * @return void
     * Returns only for a matching token whose expiration is strictly after the current time.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the matching token has reached its expiration time.
     *
     * @author Oleg Schildt
     */
    public function verifyAccessToken(?string $access_token, ?string $user_id, ?string $client_id): void;

    /**
     * Checks the exact token/user/client binding and fixed expiration under a storage lock.
     * Verification must not extend either token lifetime. Refresh-token reuse must revoke its matching
     * family before reporting failure.
     *
     * @param ?string $refresh_token
     * The raw token to verify.
     *
     * @param ?string $user_id
     * The user identifier bound to the token.
     *
     * @param ?string $client_id
     * The client identifier bound to the token.
     *
     * @return void
     * Returns only for a matching token whose expiration is strictly after the current time.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required lookup value is null or empty.
     *
     * @throws \OAuth2\InvalidTokenException
     * If a value is invalid, a token is unknown, or consumed-token reuse is detected.
     *
     * @throws \OAuth2\AuthSystemException
     * If storage cannot read, validate, lock or persist session state.
     *
     * @throws \OAuth2\TokenExpiredException
     * If the matching token has reached its expiration time.
     *
     * @author Oleg Schildt
     */
    public function verifyRefreshToken(?string $refresh_token, ?string $user_id, ?string $client_id): void;
} // ITokenStorage
