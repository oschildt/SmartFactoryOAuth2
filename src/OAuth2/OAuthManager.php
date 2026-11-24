<?php

namespace OAuth2;

use OAuth2\Interfaces\IOAuthManager;
use OAuth2\Interfaces\ITokenStorage;
use OAuth2\Interfaces\IUserAuthenticator;
use SmartFactory\SmartException;

/**
 * Issues signed JWTs and delegates atomic session operations to token storage.
 *
 * Standard JWT claims coexist with historical session claims. Revocation is
 * immediate only when verification includes storage. HTTP grants, client
 * registration, consent and endpoint transport belong to the calling application.
 *
 * @author Oleg Schildt
 */
class OAuthManager implements IOAuthManager
{
    /**
     * Stores validated settings, parsed keys and optional collaborators.
     *
     * @var array<string, mixed>
     *
     * @author Oleg Schildt
     */
    protected array $configuration = [];

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
     * @throws AuthSystemException
     * If an unknown or invalid parameter is supplied, a key cannot be loaded, its type or strength is
     * invalid, its public and private parts do not match, or the same key is assigned to
     * different algorithms.
     *
     * @author Oleg Schildt
     */
    public function init(array $parameters): void
    {
        $defaults = [
            'encryption_algorithm' => null, 'secret_key' => null, 'public_key' => null,
            'private_key' => null, 'pass_phrase' => '', 'access_token_ttl_minutes' => 10,
            'refresh_token_ttl_days' => 14, 'token_storage' => null, 'user_authenticator' => null,
            'issuer' => null, 'audience' => null, 'key_id' => null, 'verification_keys' => [],
        ];

        if (array_diff_key($parameters, $defaults) !== []) {
            throw new AuthSystemException('Unknown OAuth manager configuration parameter.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        $config = array_replace($defaults, $parameters);
        $config['access_token_ttl_minutes'] = $this->normalizeTtl($config['access_token_ttl_minutes'], 525600);
        $config['refresh_token_ttl_days'] = $this->normalizeTtl($config['refresh_token_ttl_days'], 3650);

        foreach (['token_storage' => ITokenStorage::class, 'user_authenticator' => IUserAuthenticator::class] as $name => $interface) {
            if ($config[$name] !== null && !$config[$name] instanceof $interface) {
                throw new AuthSystemException("The '$name' must implement $interface.", SmartException::ERR_CODE_CONFIG_ERROR);
            }
        }

        foreach (['issuer', 'key_id'] as $name) {
            if ($config[$name] !== null && !$this->isIdentifier($config[$name])) {
                throw new AuthSystemException("The '$name' must be a nonempty UTF-8 string.", SmartException::ERR_CODE_CONFIG_ERROR);
            }
        }

        if ($config['audience'] !== null) {
            $config['audience'] = is_string($config['audience']) ? [$config['audience']] : $config['audience'];

            if (!is_array($config['audience']) || !array_is_list($config['audience']) || $config['audience'] === []) {
                throw new AuthSystemException('The audience must be a string or a nonempty list of strings.', SmartException::ERR_CODE_CONFIG_ERROR);
            }

            foreach ($config['audience'] as $audience) {
                if (!$this->isIdentifier($audience)) {
                    throw new AuthSystemException('Every audience must be a nonempty UTF-8 string.', SmartException::ERR_CODE_CONFIG_ERROR);
                }
            }

            $config['audience'] = array_values(array_unique($config['audience']));
        }

        $config['active_key'] = $this->prepareKey($config, true);

        if (!is_array($config['verification_keys'])) {
            throw new AuthSystemException('The verification_keys parameter must be a map.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        $keys = [];

        foreach ($config['verification_keys'] as $id => $key) {
            if (
                !$this->isIdentifier((string) $id) || !is_array($key)
                || array_diff_key($key, array_flip(['encryption_algorithm', 'secret_key', 'public_key'])) !== []
            ) {
                throw new AuthSystemException('A verification key configuration is invalid.', SmartException::ERR_CODE_CONFIG_ERROR);
            }

            $keys[(string) $id] = $this->prepareKey($key, false);
        }

        if ($config['key_id'] !== null) {
            if (array_key_exists($config['key_id'], $keys)) {
                throw new AuthSystemException('The active key ID is duplicated in verification_keys.', SmartException::ERR_CODE_CONFIG_ERROR);
            }

            $keys[$config['key_id']] = $config['active_key'];
        }

        $algorithms_by_key = [];

        foreach ([$config['active_key'], ...array_values($keys)] as $key) {
            $material = $key['verification'];

            if ($material instanceof \OpenSSLAsymmetricKey) {
                $details = openssl_pkey_get_details($material);

                if ($details === false) {
                    throw new AuthSystemException('A verification key could not be inspected.', SmartException::ERR_CODE_CONFIG_ERROR);
                }

                $material = $details['key'];
            }

            $fingerprint = hash('sha256', $material);

            if (isset($algorithms_by_key[$fingerprint]) && $algorithms_by_key[$fingerprint] !== $key['algorithm']) {
                throw new AuthSystemException('Each key must be bound to exactly one algorithm.', SmartException::ERR_CODE_CONFIG_ERROR);
            }

            $algorithms_by_key[$fingerprint] = $key['algorithm'];
        }

        $config['verification_keys'] = $keys;
        $this->configuration = $config;
    } // init

    /**
     * Validates a bounded integer lifetime without floating-point overflow.
     *
     * @param mixed $value
     * An integer or decimal integer string.
     *
     * @param int $maximum
     * The inclusive upper bound in the configured time unit.
     *
     * @return int
     * Returns the validated positive lifetime.
     *
     * @throws AuthSystemException
     * If the value is not a bounded positive integer.
     *
     * @author Oleg Schildt
     */
    protected function normalizeTtl(mixed $value, int $maximum): int
    {
        if (is_string($value) && preg_match('/^[0-9]{1,10}$/D', $value)) {
            $value = (int) $value;
        }

        if (!is_int($value) || $value < 1 || $value > $maximum) {
            throw new AuthSystemException('A token lifetime is outside its supported integer range.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        return $value;
    } // normalizeTtl

    /**
     * Checks identifiers before JSON serialization or storage access.
     *
     * @param mixed $value
     * The proposed identifier.
     *
     * @return bool
     * Returns true for a nonempty UTF-8 string up to 4096 bytes without control characters. The string
     * "0" is valid; values are never trimmed or changed.
     *
     * @author Oleg Schildt
     */
    protected function isIdentifier(mixed $value): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= 4096
            && preg_match('//u', $value) === 1 && preg_match('/[\x00-\x1f\x7f]/', $value) === 0;
    } // isIdentifier

    /**
     * Loads keys and binds their validated type and strength to one algorithm.
     *
     * @param array<string, mixed> $config
     * The algorithm and raw HMAC bytes or local RSA PEM paths.
     *
     * @param bool $allow_private
     * Whether a private signing key may be supplied.
     *
     * @return array{algorithm: string, verification: string|\OpenSSLAsymmetricKey, signing: string|\OpenSSLAsymmetricKey|null}
     * Returns parsed keys; signing is null for public-key-only verification.
     *
     * @throws AuthSystemException
     * If the algorithm, key material, password, key type, pair or length is invalid.
     *
     * @author Oleg Schildt
     */
    protected function prepareKey(array $config, bool $allow_private): array
    {
        $algorithm = $config['encryption_algorithm'] ?? null;
        $sizes = ['HS256' => 32, 'HS384' => 48, 'HS512' => 64, 'RS256' => 32, 'RS384' => 48, 'RS512' => 64];

        if (!is_string($algorithm) || !isset($sizes[$algorithm])) {
            throw new AuthSystemException('An unsupported signing algorithm was configured.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (str_starts_with($algorithm, 'HS')) {
            $secret = $config['secret_key'] ?? null;

            if (!is_string($secret) || strlen($secret) < $sizes[$algorithm]) {
                throw new AuthSystemException('The HMAC key is shorter than the hash output.', SmartException::ERR_CODE_CONFIG_ERROR);
            }

            return ['algorithm' => $algorithm, 'verification' => $secret, 'signing' => $allow_private ? $secret : null];
        }

        $private = null;
        $public = null;
        $password = $config['pass_phrase'] ?? '';

        if (!is_string($password)) {
            throw new AuthSystemException('The private-key password must be a string.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if ($allow_private && ($config['private_key'] ?? null) !== null) {
            $private = @openssl_pkey_get_private($this->readKeyFile($config['private_key']), $password);

            if ($private === false) {
                throw new AuthSystemException('The private signing key could not be loaded.', SmartException::ERR_CODE_CONFIG_ERROR);
            }

            $details = openssl_pkey_get_details($private);
            $public = $details === false ? false : openssl_pkey_get_public($details['key']);
        }

        if (($config['public_key'] ?? null) !== null) {
            $public = @openssl_pkey_get_public($this->readKeyFile($config['public_key']));
        }

        if (!$public instanceof \OpenSSLAsymmetricKey) {
            throw new AuthSystemException('A valid RSA public verification key is required.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        $details = openssl_pkey_get_details($public);

        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < 2048) {
            throw new AuthSystemException('RSA keys must have type RSA and at least 2048 bits.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if ($private !== null) {
            $private_details = openssl_pkey_get_details($private);

            if ($private_details === false || $private_details['type'] !== OPENSSL_KEYTYPE_RSA || $private_details['key'] !== $details['key']) {
                throw new AuthSystemException('The RSA public and private keys do not form a pair.', SmartException::ERR_CODE_CONFIG_ERROR);
            }
        }

        return ['algorithm' => $algorithm, 'verification' => $public, 'signing' => $private];
    } // prepareKey

    /**
     * Reads a local PEM key without accepting stream wrappers.
     *
     * @param mixed $path
     * A readable local file path.
     *
     * @return string
     * Returns the complete nonempty PEM contents.
     *
     * @throws AuthSystemException
     * If the path is invalid or the key file cannot be read.
     *
     * @author Oleg Schildt
     */
    protected function readKeyFile(mixed $path): string
    {
        if (!is_string($path) || $path === '' || str_contains($path, "\0") || str_contains($path, '://') || !is_file($path)) {
            throw new AuthSystemException('A signing-key path is not a local file.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        $pem = @file_get_contents($path);

        if ($pem === false || $pem === '') {
            throw new AuthSystemException('A signing-key file could not be read.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        return $pem;
    } // readKeyFile

    /**
     * Ensures that configuration was successfully initialized.
     *
     * @return void
     * Permits operations on an initialized manager.
     *
     * @throws AuthSystemException
     * If init() has not completed successfully.
     *
     * @author Oleg Schildt
     */
    protected function validateParameters(): void
    {
        if ($this->configuration === []) {
            throw new AuthSystemException('The OAuth manager has not been initialized.', SmartException::ERR_CODE_CONFIG_ERROR);
        }
    } // validateParameters

    /**
     * Encodes bytes using unpadded Base64URL.
     *
     * @param string $data
     * The binary or UTF-8 data to encode.
     *
     * @return string
     * Returns the URL-safe encoding without padding or line breaks.
     *
     * @author Oleg Schildt
     */
    protected function urlSafeB64Encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    } // urlSafeB64Encode

    /**
     * Decodes a canonical, nonempty Base64URL segment.
     *
     * @param string $b64
     * An unpadded segment containing only the Base64URL alphabet.
     *
     * @return string
     * Returns the decoded bytes.
     *
     * @throws InvalidTokenException
     * If the alphabet, length or unused trailing bits are invalid.
     *
     * @author Oleg Schildt
     */
    protected function urlSafeB64Decode(string $b64): string
    {
        if ($b64 === '' || !preg_match('/^[A-Za-z0-9_-]+$/D', $b64) || strlen($b64) % 4 === 1) {
            throw new InvalidTokenException('A JWT segment has invalid Base64URL encoding.');
        }

        $decoded = base64_decode(strtr($b64, '-_', '+/'), true);

        if ($decoded === false || $this->urlSafeB64Encode($decoded) !== $b64) {
            throw new InvalidTokenException('A JWT segment is not canonically encoded.');
        }

        return $decoded;
    } // urlSafeB64Decode

    /**
     * Generates an opaque token using the operating system cryptographic generator.
     *
     * @return string
     * Returns 32 random bytes encoded as 64 lowercase hexadecimal characters.
     *
     * @throws AuthSystemException
     * If the cryptographic generator fails; no weaker fallback is used.
     *
     * @author Oleg Schildt
     */
    protected function generateToken(): string
    {
        try {
            return bin2hex(random_bytes(32));
        } catch (\Random\RandomException $exception) {
            throw new AuthSystemException('A secure token could not be generated.', previous: $exception);
        }
    } // generateToken

    /**
     * Signs a serialized JWT with the configured active key.
     *
     * @param string $input
     * The encoded header and payload separated by a period.
     *
     * @return string
     * Returns the binary HMAC or RSA signature.
     *
     * @throws AuthSystemException
     * If initialization, a private signing key or RSA signing is unavailable.
     *
     * @author Oleg Schildt
     */
    protected function generateJwtSignature(string $input): string
    {
        $this->validateParameters();

        $key = $this->configuration['active_key'];
        $algorithm = $key['algorithm'];
        $hash = 'sha' . substr($algorithm, 2);

        if ($key['signing'] === null) {
            throw new AuthSystemException('This manager has no private signing key.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (str_starts_with($algorithm, 'HS')) {
            return hash_hmac($hash, $input, $key['signing'], true);
        }

        $signature = '';

        if (!@openssl_sign($input, $signature, $key['signing'], $hash)) {
            throw new AuthSystemException('The access token could not be signed.');
        }

        return $signature;
    } // generateJwtSignature

    /**
     * Serializes and signs claims before any storage update occurs.
     *
     * @param array<string, mixed> $payload
     * JSON-compatible session claims.
     *
     * @return string
     * Returns the compact signed JWT, limited to 16384 bytes.
     *
     * @throws AuthSystemException
     * If serialization or signing fails, or the token exceeds the size limit.
     *
     * @author Oleg Schildt
     */
    protected function createJwtToken(array $payload): string
    {
        $this->validateParameters();

        $header = ['typ' => 'JWT', 'alg' => $this->configuration['encryption_algorithm']];

        if ($this->configuration['key_id'] !== null) {
            $header['kid'] = $this->configuration['key_id'];
        }

        try {
            $input = $this->urlSafeB64Encode(json_encode($header, JSON_THROW_ON_ERROR)) . '.'
                . $this->urlSafeB64Encode(json_encode($payload, JSON_THROW_ON_ERROR));
        } catch (\JsonException $exception) {
            throw new AuthSystemException('The access-token claims could not be serialized.', previous: $exception);
        }

        $token = $input . '.' . $this->urlSafeB64Encode($this->generateJwtSignature($input));

        if (strlen($token) > 16384) {
            throw new AuthSystemException('The access token exceeds the supported size.');
        }

        return $token;
    } // createJwtToken

    /**
     * Parses a JWT and verifies its signature using locally configured keys only.
     *
     * @param ?string $jwt_access_token
     * A compact signed access token; null and empty strings are rejected.
     *
     * @param bool $verify_signature
     * Must be true; unverified extraction is deliberately unavailable.
     *
     * @return array<string, mixed>
     * Returns an object-shaped payload after successful signature verification.
     *
     * @throws MissingParametersException
     * If the JWT is null or empty.
     *
     * @throws InvalidTokenException
     * If encoding, JSON objects, header, key ID, algorithm or signature is invalid.
     *
     * @throws AuthSystemException
     * If the manager is uninitialized or cryptographic verification fails internally.
     *
     * @author Oleg Schildt
     */
    protected function getJwtPayload(?string $jwt_access_token, bool $verify_signature = true): array
    {
        $this->validateParameters();

        if ($jwt_access_token === null || $jwt_access_token === '') {
            throw new MissingParametersException('The access token is not specified.');
        }

        if (!$verify_signature || strlen($jwt_access_token) > 16384) {
            throw new InvalidTokenException('The JWT cannot be processed.');
        }

        $segments = explode('.', $jwt_access_token);

        if (count($segments) !== 3) {
            throw new InvalidTokenException('The JWT must contain exactly three segments.');
        }

        [$head, $body, $signature] = $segments;
        $header_json = $this->urlSafeB64Decode($head);
        $payload_json = $this->urlSafeB64Decode($body);
        $signature = $this->urlSafeB64Decode($signature);

        try {
            $header = json_decode($header_json, false, 64, JSON_THROW_ON_ERROR);
            $payload = json_decode($payload_json, false, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new InvalidTokenException('The JWT contains invalid JSON.', previous: $exception);
        }

        if (!$header instanceof \stdClass || !$payload instanceof \stdClass) {
            throw new InvalidTokenException('The JWT header and payload must be JSON objects.');
        }

        if (
            ($header->typ ?? null) !== 'JWT' || !isset($header->alg) || !is_string($header->alg)
            || property_exists($header, 'crit') || property_exists($header, 'b64')
        ) {
            throw new InvalidTokenException('The JWT header contains unsupported parameters.');
        }

        $key = $this->configuration['active_key'];

        if (property_exists($header, 'kid')) {
            if (!$this->isIdentifier($header->kid) || !array_key_exists($header->kid, $this->configuration['verification_keys'])) {
                throw new InvalidTokenException('The JWT key ID is unknown.');
            }

            $key = $this->configuration['verification_keys'][$header->kid];
        } elseif ($this->configuration['key_id'] !== null) {
            throw new InvalidTokenException('The JWT key ID is missing.');
        }

        if ($header->alg !== $key['algorithm']) {
            throw new InvalidTokenException('The JWT algorithm does not match its configured key.');
        }

        $input = "$head.$body";
        $hash = 'sha' . substr($key['algorithm'], 2);

        if (str_starts_with($key['algorithm'], 'HS')) {
            if (!hash_equals(hash_hmac($hash, $input, $key['verification'], true), $signature)) {
                throw new InvalidTokenException('The JWT signature is invalid.');
            }
        } else {
            $result = @openssl_verify($input, $signature, $key['verification'], $hash);

            if ($result === -1 || $result === false) {
                throw new AuthSystemException('The JWT signature could not be checked.');
            }

            if ($result !== 1) {
                throw new InvalidTokenException('The JWT signature is invalid.');
            }
        }

        // Preserve object-shaped roots while exposing nested claims as ordinary arrays.
        return json_decode($payload_json, true, 64, JSON_THROW_ON_ERROR);
    } // getJwtPayload

    /**
     * Validates session claims and configured issuer and audience restrictions.
     *
     * @param array<string, mixed> $payload
     * The signature-verified JWT claims.
     *
     * @param bool $check_time
     * Whether to enforce expiry and not-before time; revocation may inspect expired JWTs.
     *
     * @return void
     * Accepts consistent string identifiers and integer Unix timestamps.
     *
     * @throws InvalidTokenException
     * If required claims, their types, relationships, issuer or audience are invalid.
     *
     * @throws TokenExpiredException
     * If time checking is enabled and the access token has reached its expiration time.
     *
     * @author Oleg Schildt
     */
    protected function validatePayload(array $payload, bool $check_time): void
    {
        foreach (['access_token', 'user_id', 'client_id', 'sub', 'jti'] as $name) {
            if (!$this->isIdentifier($payload[$name] ?? null)) {
                throw new InvalidTokenException("The JWT claim '$name' is invalid.");
            }
        }

        foreach (['access_token_expire', 'exp', 'iat'] as $name) {
            if (!isset($payload[$name]) || !is_int($payload[$name]) || $payload[$name] < 0) {
                throw new InvalidTokenException("The JWT claim '$name' must be an integer timestamp.");
            }
        }

        if (
            $payload['sub'] !== $payload['user_id'] || $payload['jti'] !== $payload['access_token']
            || $payload['exp'] !== $payload['access_token_expire'] || $payload['iat'] >= $payload['exp']
        ) {
            throw new InvalidTokenException('The JWT claims are inconsistent.');
        }

        if (array_key_exists('nbf', $payload) && (!is_int($payload['nbf']) || $payload['nbf'] < 0 || $payload['nbf'] >= $payload['exp'])) {
            throw new InvalidTokenException('The JWT not-before claim is invalid.');
        }

        if ($this->configuration['issuer'] !== null && ($payload['iss'] ?? null) !== $this->configuration['issuer']) {
            throw new InvalidTokenException('The JWT issuer is invalid.');
        }

        if (array_key_exists('iss', $payload) && !$this->isIdentifier($payload['iss'])) {
            throw new InvalidTokenException('The JWT issuer must be a nonempty string.');
        }

        $audiences = $payload['aud'] ?? null;

        if (array_key_exists('aud', $payload)) {
            $audiences = is_string($audiences) ? [$audiences] : $audiences;

            if (!is_array($audiences) || !array_is_list($audiences) || $audiences === []) {
                throw new InvalidTokenException('The JWT audience is invalid.');
            }

            foreach ($audiences as $audience) {
                if (!$this->isIdentifier($audience)) {
                    throw new InvalidTokenException('A JWT audience is invalid.');
                }
            }
        }

        if ($this->configuration['audience'] !== null && ($audiences === null || array_intersect($this->configuration['audience'], $audiences) === [])) {
            throw new InvalidTokenException('The JWT is intended for a different audience.');
        }

        if ($check_time) {
            $now = $this->getCurrentTime();

            if ($now >= $payload['exp']) {
                throw new TokenExpiredException('The access token has expired.');
            }

            if ($payload['iat'] > $now || ($payload['nbf'] ?? 0) > $now) {
                throw new InvalidTokenException('The access token is not valid yet.');
            }
        }
    } // validatePayload

    /**
     * Supplies the wall clock for token issuance and JWT lifetime checks.
     *
     * @return int
     * Returns the current Unix timestamp in seconds.
     *
     * @author Oleg Schildt
     */
    protected function getCurrentTime(): int
    {
        return time();
    } // getCurrentTime

    /**
     * Returns storage for operations requiring server-side session state.
     *
     * @return ITokenStorage
     * Returns the collaborator supplied by the caller.
     *
     * @throws AuthSystemException
     * If the manager is uninitialized or storage was not configured.
     *
     * @author Oleg Schildt
     */
    protected function getStorage(): ITokenStorage
    {
        $this->validateParameters();

        if ($this->configuration['token_storage'] === null) {
            throw new AuthSystemException('Token storage is required for this operation.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        return $this->configuration['token_storage'];
    } // getStorage

    /**
     * Validates request identifiers without treating the string "0" as empty.
     *
     * @param ?string $value
     * The request value to check.
     *
     * @param string $name
     * The parameter name used in error messages.
     *
     * @return string
     * Returns the original valid UTF-8 string.
     *
     * @throws MissingParametersException
     * If the parameter is null or empty.
     *
     * @throws InvalidTokenException
     * If it contains invalid UTF-8, control characters or too many bytes.
     *
     * @author Oleg Schildt
     */
    protected function requireIdentifier(?string $value, string $name): string
    {
        if ($value === null || $value === '') {
            throw new MissingParametersException("The '$name' is not specified.");
        }

        if (!$this->isIdentifier($value)) {
            throw new InvalidTokenException("The '$name' is invalid.");
        }

        return $value;
    } // requireIdentifier

    /**
     * Builds a session and commits it before publishing tokens in the response.
     *
     * @param string $user_id
     * The authenticated user identifier.
     *
     * @param string $client_id
     * The client or device identifier scoped to this user.
     *
     * @param array<string, mixed> &$response
     * Receives the committed response and remains unchanged on failure.
     *
     * @param ?string $previous_refresh_token
     * The refresh token to atomically consume, or null for a new authenticated family.
     *
     * @return void
     * Publishes user_id, client_id, access_token (the JWT), jwt_access_token (its compatibility
     * alias), token_type (Bearer), expires_in (seconds), both absolute expiry timestamps and
     * refresh_token. The internal opaque access ID and last_activity are not response fields.
     *
     * @throws AuthSystemException
     * If signing, random generation, timestamp arithmetic or storage configuration fails.
     *
     * @throws InvalidTokenException
     * If identifiers are invalid or rotation rejects an unknown or consumed refresh token.
     *
     * @throws TokenExpiredException
     * If the refresh token expires before atomic replacement.
     *
     * @throws \Exception
     * If storage cannot persist the session.
     *
     * @author Oleg Schildt
     */
    protected function createTokenRecord(
        string $user_id,
        string $client_id,
        array &$response,
        ?string $previous_refresh_token = null
    ): void {
        $storage = $this->getStorage();
        $user_id = $this->requireIdentifier($user_id, 'user_id');
        $client_id = $this->requireIdentifier($client_id, 'client_id');
        $now = $this->getCurrentTime();
        $access_seconds = $this->configuration['access_token_ttl_minutes'] * 60;
        $refresh_seconds = $this->configuration['refresh_token_ttl_days'] * 86400;

        if ($now < 0 || $now > PHP_INT_MAX - max($access_seconds, $refresh_seconds)) {
            throw new AuthSystemException('The token expiration timestamp would overflow.');
        }

        $record = [
            'user_id' => $user_id, 'client_id' => $client_id, 'last_activity' => $now,
            'refresh_token' => $this->generateToken(), 'refresh_token_expire' => $now + $refresh_seconds,
            'access_token' => $this->generateToken(), 'access_token_expire' => $now + $access_seconds,
        ];
        $payload = [
            'access_token' => $record['access_token'], 'access_token_expire' => $record['access_token_expire'],
            'user_id' => $user_id, 'client_id' => $client_id, 'sub' => $user_id,
            'jti' => $record['access_token'], 'iat' => $now, 'exp' => $record['access_token_expire'],
        ];

        foreach (['issuer' => 'iss', 'audience' => 'aud'] as $setting => $claim) {
            if ($this->configuration[$setting] !== null) {
                $payload[$claim] = $this->configuration[$setting];
            }
        }

        $jwt = $this->createJwtToken($payload);

        if ($previous_refresh_token === null) {
            $storage->saveTokenRecord($record);
        } else {
            $storage->rotateTokenRecord($previous_refresh_token, $record);
        }

        $response = [
            'user_id' => $user_id, 'client_id' => $client_id, 'access_token' => $jwt,
            'jwt_access_token' => $jwt, 'token_type' => 'Bearer', 'expires_in' => $access_seconds,
            'access_token_expire' => $record['access_token_expire'],
            'refresh_token' => $record['refresh_token'], 'refresh_token_expire' => $record['refresh_token_expire'],
        ];
    } // createTokenRecord

    /**
     * Authenticates credentials and creates a new session for the supplied client.
     *
     * @param array<string, mixed> $credentials
     * Authenticator-specific credentials and a nonempty string client_id.
     *
     * @param array<string, mixed> &$response
     * Receives the committed token response described by createTokenRecord(); remains unchanged on
     * failure.
     *
     * @return void
     * Publishes tokens only after authentication and successful persistence.
     *
     * @throws MissingParametersException
     * If client_id or an authenticator-required credential is missing.
     *
     * @throws InvalidCredentialsException
     * If the authenticator rejects credentials or client_id has an invalid type.
     *
     * @throws InvalidTokenException
     * If the client or returned user identifier is invalid.
     *
     * @throws AuthSystemException
     * If configuration, the authenticator, signing or storage is unavailable.
     *
     * @throws \Exception
     * If the authenticator identity backend or storage fails.
     *
     * @author Oleg Schildt
     */
    public function authenticateUser(array $credentials, array &$response): void
    {
        $this->validateParameters();

        $client_id = $credentials['client_id'] ?? null;

        if ($client_id !== null && !is_string($client_id)) {
            throw new InvalidCredentialsException('The client_id must be a string.');
        }

        $client_id = $this->requireIdentifier($client_id, 'client_id');
        $authenticator = $this->configuration['user_authenticator'];

        if ($authenticator === null) {
            throw new AuthSystemException('A user authenticator is required.', SmartException::ERR_CODE_CONFIG_ERROR);
        }

        $user_id = $authenticator->authenticateUser($credentials);

        $this->createTokenRecord((string) $user_id, $client_id, $response);
    } // authenticateUser

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
     * @throws MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function refreshTokens(?string $refresh_token, ?string $user_id, ?string $client_id, array &$response): void
    {
        $refresh_token = $this->requireIdentifier($refresh_token, 'refresh_token');
        $user_id = $this->requireIdentifier($user_id, 'user_id');
        $client_id = $this->requireIdentifier($client_id, 'client_id');

        $this->createTokenRecord($user_id, $client_id, $response, $refresh_token);
    } // refreshTokens

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
     * @throws MissingParametersException
     * If the JWT is null or empty.
     *
     * @throws InvalidTokenException
     * If encoding, signature, claims or the stored session are invalid.
     *
     * @throws TokenExpiredException
     * If the JWT or stored access token has reached its expiration time.
     *
     * @throws AuthSystemException
     * If initialization or a required cryptographic or storage service fails.
     *
     * @throws \Exception
     * If storage cannot check the session.
     *
     * @author Oleg Schildt
     */
    public function verifyJwtAccessToken(?string $jwt_access_token, bool $check_on_server = true): array
    {
        $payload = $this->getJwtPayload($jwt_access_token);

        $this->validatePayload($payload, true);

        if ($check_on_server) {
            $this->getStorage()->verifyAccessToken($payload['access_token'], $payload['user_id'], $payload['client_id']);
        }

        return $payload;
    } // verifyJwtAccessToken

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
     * @throws MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function verifyRefreshToken(?string $refresh_token, ?string $user_id, ?string $client_id): void
    {
        $this->getStorage()->verifyRefreshToken(
            $this->requireIdentifier($refresh_token, 'refresh_token'),
            $this->requireIdentifier($user_id, 'user_id'),
            $this->requireIdentifier($client_id, 'client_id')
        );
    } // verifyRefreshToken

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
     * @throws MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function invalidateUser(?string $user_id, ?string $client_id, ?string $refresh_token): void
    {
        $this->getStorage()->revokeTokenRecords(
            $this->requireIdentifier($refresh_token, 'refresh_token'),
            $this->requireIdentifier($user_id, 'user_id'),
            $this->requireIdentifier($client_id, 'client_id'),
            true
        );
    } // invalidateUser

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
     * @throws MissingParametersException
     * If a required argument is null or empty.
     *
     * @throws InvalidTokenException
     * If an argument is invalid, the token is unknown, or reuse is detected.
     *
     * @throws TokenExpiredException
     * If the refresh token has reached its expiration time.
     *
     * @throws AuthSystemException
     * If configuration, signing, random generation or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot complete its operation.
     *
     * @author Oleg Schildt
     */
    public function invalidateClient(?string $user_id, ?string $client_id, ?string $refresh_token): void
    {
        $this->getStorage()->revokeTokenRecords(
            $this->requireIdentifier($refresh_token, 'refresh_token'),
            $this->requireIdentifier($user_id, 'user_id'),
            $this->requireIdentifier($client_id, 'client_id'),
            false
        );
    } // invalidateClient

    /**
     * Revokes a session identified by a correctly signed JWT, including an expired JWT.
     *
     * @param ?string $jwt_access_token
     * The signed token whose opaque access ID identifies the session.
     *
     * @return void
     * Removes the matching access/refresh pair; already absent records are ignored.
     *
     * @throws MissingParametersException
     * If the JWT is null or empty.
     *
     * @throws InvalidTokenException
     * If its signature, format or session claims are invalid.
     *
     * @throws AuthSystemException
     * If configuration, cryptographic verification or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot persist revocation.
     *
     * @author Oleg Schildt
     */
    public function invalidateJwtAccessToken(?string $jwt_access_token): void
    {
        $payload = $this->getJwtPayload($jwt_access_token);

        $this->validatePayload($payload, false);

        $this->getStorage()->deleteTokenRecordByKey('access_token', $payload['access_token']);
    } // invalidateJwtAccessToken

    /**
     * Revokes a session by possession of a current or previously consumed refresh token.
     *
     * @param ?string $refresh_token
     * The nonempty refresh token identifying the family; it need not be unexpired.
     *
     * @return void
     * Removes its active token family. Unknown tokens are ignored for idempotent revocation.
     *
     * @throws MissingParametersException
     * If the refresh token is null or empty.
     *
     * @throws InvalidTokenException
     * If the token contains invalid characters or exceeds the size limit.
     *
     * @throws AuthSystemException
     * If configuration or storage access fails.
     *
     * @throws \Exception
     * If the storage collaborator cannot persist revocation.
     *
     * @author Oleg Schildt
     */
    public function invalidateRefreshToken(?string $refresh_token): void
    {
        $this->getStorage()->deleteTokenRecordByKey('refresh_token', $this->requireIdentifier($refresh_token, 'refresh_token'));
    } // invalidateRefreshToken
} // OAuthManager
