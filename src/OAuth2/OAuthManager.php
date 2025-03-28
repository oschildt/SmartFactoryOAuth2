<?php
/**
 * This file contains the implementation of the interface IOAuthManager for secure user authentication.
 *
 * @author Oleg Schildt
 */

namespace OAuth2;

use \OAuth2\Interfaces\IOAuthManager;
use \OAuth2\Interfaces\ITokenStorage;
use \OAuth2\Interfaces\IUserAuthenticator;

use \SmartFactory\SmartException;

/**
 * Class for secure user authentication.
 *
 * @author Oleg Schildt
 */
class OAuthManager implements IOAuthManager
{
    /**
     * Internal reference to the token storage object.
     *
     * It must implement {@see \OAuth2\Interfaces\ITokenStorage}.
     *
     * @var \OAuth2\Interfaces\ITokenStorage
     *
     * @author Oleg Schildt
     */
    protected $token_storage = null;

    /**
     * Internal reference to the user authenticator object.
     *
     * It must implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     *
     * @var \OAuth2\Interfaces\IUserAuthenticator
     *
     * @author Oleg Schildt
     */
    protected $user_authenticator = null;

    /**
     * Internal property for storing the sekret key.
     *
     * The secret key is required for the algoritms HS256, HS384, HS512.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $secret_key = null;

    /**
     * Internal property for storing the encryption algorithm.
     *
     * The supported algorithms are HS256, HS384, HS512, RS256, RS384, RS512.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $encryption_algorithm = null;

    /**
     * Internal property for storing the time to live of the access token.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $access_token_ttl_minutes = null;

    /**
     * Internal property for storing the time to live of the refresh token.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $refresh_token_ttl_days = null;

    /**
     * Internal property for storing the path to the public key file.
     *
     * Required for the algorithms: RS256, RS384, RS512.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $public_key = null;

    /**
     * Internal property for storing the path to the provate key file.
     *
     * Required for the algorithms: RS256, RS384, RS512.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $private_key = null;

    /**
     * Internal property for storing the pass phrase for the private key.
     *
     * Only required, if the private key was generated with a pass phrase.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $pass_phrase = "";

    /**
     * Internal property for the list of supported algorithms.
     *
     * @var array
     *
     * @author Oleg Schildt
     */
    protected $supported_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'];

    /**
     * Internal auxiliary function for safe base64 encoding.
     *
     * @param string $data
     * Data to be encoded.
     *
     * @return string
     * Returns the base64 encoded data string.
     *
     * @see OAuthManager::urlSafeB64Decode()
     *
     * @author Oleg Schildt
     */
    protected function urlSafeB64Encode($data)
    {
        $b64 = base64_encode($data);
        $b64 = str_replace(array('+', '/', "\r", "\n", '='), array('-', '_'), $b64);

        return $b64;
    }

    /**
     * Internal auxiliary function for safe base64 decoding.
     *
     * @param string $b64
     * Data to be decoded.
     *
     * @return string
     * Returns the base64 decoded data string.
     *
     * @see OAuthManager::urlSafeB64Encode()
     *
     * @author Oleg Schildt
     */
    protected function urlSafeB64Decode($b64)
    {
        $b64 = str_replace(array('-', '_'), array('+', '/'), $b64);

        return base64_decode($b64);
    }

    /**
     * Internal auxiliary function for verification of the data signature for the algorithms
     * RS256, RS384, RS512.
     *
     * @param string $input
     * Data which is signed.
     *
     * @param string $signature
     * Signature used for signing the data.
     *
     * @param string $algorithm_id
     * Algorithm used for signing. The supported algorithms are: RS256, RS384, RS512.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the public key is invalid.
     * - if the ssl verification cannot be performed due to system errors.
     *
     * @uses OAuthManager::generateRSASignature()
     *
     * @author Oleg Schildt
     */
    protected function verifyRSASignature($input, $signature, $algorithm_id)
    {
        $this->validateParameters();

        $public_key = @openssl_pkey_get_public("file://" . $this->public_key);
        if ($public_key === false) {
            throw new AuthSystemException(sprintf("The public key file '%s' is not valid!\n\nError: %s", $this->public_key, openssl_error_string()), SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        $result = @openssl_verify($input, $signature, $public_key, $algorithm_id);

        if ($result === -1 || $result === false) {
            throw new AuthSystemException(sprintf("Error by data verification:\n\n%s", openssl_error_string()), SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        if ($result === 0) {
            throw new InvalidTokenException("The signature of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }
    }

    /**
     * Internal auxiliary function for generation of the signature of the data for the algorithms
     * RS256, RS384, RS512.
     *
     * @param string $input
     * Data which is signed.
     *
     * @param string $algorithm_id
     * Algorithm to use for signing. The supported algorithms are: RS256, RS384, RS512.
     *
     * @return string
     * Returns the signature of the data.
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the private key is invalid.
     * - if ssl signing fails due to system errors.
     *
     * @see OAuthManager::verifyRSASignature()
     *
     * @author Oleg Schildt
     */
    protected function generateRSASignature($input, $algorithm_id)
    {
        $this->validateParameters();

        $private_key = @openssl_pkey_get_private("file://" . $this->private_key, $this->pass_phrase);
        if ($private_key === false) {
            throw new AuthSystemException(sprintf("The private key file '%s' or the pass phrase is not valid!\n\nError: %s", $this->private_key, openssl_error_string()), SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        $signature = "";
        if (!@openssl_sign($input, $signature, $private_key, $algorithm_id)) {
            throw new AuthSystemException(sprintf("Error by signing data:\n\n%s", openssl_error_string()), SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        return $signature;
    }

    /**
     * Internal auxiliary function for generation of the signature of the data for all supported algorithms.
     *
     * @param string $input
     * Data to be signed.
     *
     * @return string
     * Returns the signature of the data.
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the private key is invalid.
     * - if ssl signing fails due to system errors.
     *
     * @uses OAuthManager::generateRSASignature()
     *
     * @author Oleg Schildt
     */
    protected function generateJwtSignature($input)
    {
        switch ($this->encryption_algorithm) {
            case 'HS256':
                return hash_hmac('sha256', $input, $this->secret_key, true);

            case 'HS384':
                return hash_hmac('sha384', $input, $this->secret_key, true);

            case 'HS512':
                return hash_hmac('sha512', $input, $this->secret_key, true);

            case 'RS256':
                return $this->generateRSASignature($input, OPENSSL_ALGO_SHA256);

            case 'RS384':
                return $this->generateRSASignature($input, OPENSSL_ALGO_SHA384);

            case 'RS512':
                return $this->generateRSASignature($input, OPENSSL_ALGO_SHA512);

            default:
                throw new AuthSystemException(sprintf("Unsupported or invalid signing algorithm '%s'.", $this->encryption_algorithm), SmartException::ERR_CODE_SYSTEM_ERROR);
        }
    }

    /**
     * Internal auxiliary function for verification of the signature of the data for all supported algorithms.
     *
     * @param string $input
     * Data which was signed.
     *
     * @param string $signature
     * Signature used for signing.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the public key is invalid.
     * - if the ssl verification cannot be performed due to system errors.
     *
     * @uses OAuthManager::verifyRSASignature()
     *
     * @author Oleg Schildt
     */
    protected function verifyJwtSignature($input, $signature)
    {
        switch ($this->encryption_algorithm) {
            case'HS256':
            case'HS384':
            case'HS512':
                if (!hash_equals($this->generateJwtSignature($input), $signature)) {
                    throw new InvalidTokenException("The signature of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
                }
                break;

            case 'RS256':
                $this->verifyRSASignature($input, $signature, OPENSSL_ALGO_SHA256);
                break;

            case 'RS384':
                $this->verifyRSASignature($input, $signature, OPENSSL_ALGO_SHA384);
                break;

            case 'RS512':
                $this->verifyRSASignature($input, $signature, OPENSSL_ALGO_SHA512);
                break;

            default:
                throw new AuthSystemException(sprintf("Unsupported or invalid signing algorithm '%s'.", $this->encryption_algorithm), SmartException::ERR_CODE_SYSTEM_ERROR);
        }
    }

    /**
     * Internal auxiliary function for generation of a token string.
     *
     * @return string
     * Returns the token string.
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if ssl funtions fail due to system errors.
     *
     * @author Oleg Schildt
     */
    protected function generateToken()
    {
        if (function_exists('random_bytes')) {
            $randomData = random_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }

        if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }

        // last resort which you probably should just get rid of:
        $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);

        return substr(hash('sha512', $randomData), 0, 40);
    } // generateToken

    /**
     * Internal auxiliary function for creation of the jwt token.
     *
     * @param array $payload
     * The payload array.
     *
     * @return string
     * Returns the jwt token string.
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the private key is invalid.
     * - if ssl signing fails due to system errors.
     *
     * @author Oleg Schildt
     */
    protected function createJwtToken($payload)
    {
        $header = ["typ" => "JWT", "alg" => $this->encryption_algorithm];

        $segments = [$this->urlSafeB64Encode(json_encode($header)), $this->urlSafeB64Encode(json_encode($payload))];

        $signature = $this->generateJwtSignature(implode('.', $segments));

        $segments[] = $this->urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * Internal auxiliary function for extraction of the payload from the jwt access token.
     *
     * @param string $jwt_access_token
     * The jwt access token.
     *
     * @param boolean $verify_signature
     * The flag to control whether the signature should be verified or not.
     *
     * @return array
     * Returns the extracted payload array.
     *
     * @throws \Exception
     * It might throw an exception in the case of any errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the public key is invalid.
     * - if the ssl verification cannot be performed due to system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It might throw the InvalidTokenException if the jwt access token is invalid.
     *
     * @author Oleg Schildt
     */
    protected function getJwtPayload($jwt_access_token, $verify_signature = true)
    {
        if (!strpos($jwt_access_token, '.')) {
            throw new InvalidTokenException("The format of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        $segements = explode('.', $jwt_access_token);

        if (count($segements) != 3) {
            throw new InvalidTokenException("The format of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        list($headb64, $payloadb64, $cryptob64) = $segements;

        if (null === ($header = json_decode($this->urlSafeB64Decode($headb64), true))) {
            throw new InvalidTokenException("The header of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (null === $payload = json_decode($this->urlSafeB64Decode($payloadb64), true)) {
            throw new InvalidTokenException("The payload of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (!$verify_signature) {
            return $payload;
        }

        if (empty($header['alg'])) {
            throw new InvalidTokenException("The signing algorithm of the JWT access token is missing in the header!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        $signature = $this->urlSafeB64Decode($cryptob64);

        if (!in_array($header['alg'], $this->supported_algorithms)) {
            throw new InvalidTokenException("The signing algorithm of the JWT access token is invalid!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        $this->verifyJwtSignature("$headb64.$payloadb64", $signature);

        return $payload;
    }

    /**
     * Internal auxiliary function for validation of the parameters.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     *
     * @used_by verifyRSASignature()
     * @used_by generateRSASignature()
     * @used_by init()
     *
     * @author Oleg Schildt
     */
    protected function validateParameters()
    {
        if (!function_exists("openssl_pkey_get_private")) {
            throw new AuthSystemException("The extension 'open_ssl' is not installed!", SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        if (empty($this->access_token_ttl_minutes) || !is_numeric($this->access_token_ttl_minutes) || $this->access_token_ttl_minutes < 1) {
            throw new AuthSystemException("The 'access_token_ttl_minutes' is not specified or invalid!", SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (empty($this->refresh_token_ttl_days) || !is_numeric($this->refresh_token_ttl_days) || $this->refresh_token_ttl_days < 1) {
            throw new AuthSystemException("The 'refresh_token_ttl_days' is not specified or invalid!", SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (empty($this->token_storage)) {
            throw new AuthSystemException("The 'token_storage' is not specified!", SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (!$this->token_storage instanceof ITokenStorage) {
            throw new AuthSystemException(sprintf("The 'token_storage' does not implement the interface '%s'!", ITokenStorage::class), SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        if (empty($this->user_authenticator)) {
            throw new AuthSystemException("The 'user_authenticator' is not specified!", SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (!$this->user_authenticator instanceof IUserAuthenticator) {
            throw new AuthSystemException(sprintf("The 'user_authenticator' does not implement the interface '%s'!", IUserAuthenticator::class), SmartException::ERR_CODE_SYSTEM_ERROR);
        }

        if (empty($this->encryption_algorithm)) {
            throw new AuthSystemException("The encryption algorithm is not specified!", SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (!in_array($this->encryption_algorithm, $this->supported_algorithms)) {
            throw new AuthSystemException(sprintf("The encryption algorithm %s is not supported! The suppoted algoritms are: %s", $this->encryption_algorithm, implode(", ", $this->supported_algorithms)), SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (in_array($this->encryption_algorithm, ['HS256', 'HS384', 'HS512']) && empty($this->secret_key)) {
            throw new AuthSystemException(sprintf("The encryption algorithm %s requires a secret key! Set the parameter 'secret_key'.", $this->encryption_algorithm), SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (in_array($this->encryption_algorithm, ['RS256', 'RS384', 'RS512']) && (empty($this->public_key) || empty($this->private_key))) {
            throw new AuthSystemException(sprintf("The encryption algorithm %s requires a public key and a private key! Set the parameters 'public_key' and 'private_key'.", $this->encryption_algorithm), SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (!file_exists($this->private_key)) {
            throw new AuthSystemException(sprintf("The private key file '%s' does not exists!", $this->private_key), SmartException::ERR_CODE_CONFIG_ERROR);
        }

        if (!file_exists($this->public_key)) {
            throw new AuthSystemException(sprintf("The public key file '%s' does not exists!", $this->public_key), SmartException::ERR_CODE_CONFIG_ERROR);
        }
    }

    /**
     * Internal auxiliary function for creation of the token record.
     *
     * @param string $user_id
     * The user id for which the tokens were issued.
     *
     * @param string $client_id
     * The client id for which the tokens were issued.
     *
     * @param array &$response
     * The response to be filled with the user data and tokens.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the private key is invalid.
     * - if ssl signing fails due to system errors.
     * - if the token storage fails to save the token record.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::saveTokenRecord()
     *
     * @author Oleg Schildt
     */
    protected function createTokenRecord($user_id, $client_id, &$response)
    {
        $response["user_id"] = $user_id;
        $response["client_id"] = $client_id;

        $response["last_activity"] = time();

        $response["refresh_token"] = $this->generateToken();
        $response["refresh_token_expire"] = time() + $this->refresh_token_ttl_days * 24 * 3600;

        $response["access_token"] = $this->generateToken();
        $response["access_token_expire"] = time() + $this->access_token_ttl_minutes * 60;

        $payload = ["access_token" => $response["access_token"], "access_token_expire" => $response["access_token_expire"], "user_id" => $user_id, "client_id" => $client_id];

        $response["jwt_access_token"] = $this->createJwtToken($payload);

        $this->token_storage->saveTokenRecord($response);

        unset($response["access_token"]);
        unset($response["last_activity"]);
    }

    /**
     * Initializes the authentication manager with parameters.
     *
     * @param array $parameters
     * The parameters are:
     *
     * - $parameters["access_token_ttl_minutes"] - time to live in minutes for the access token.
     * - $parameters["refresh_token_ttl_days"] - time to live in days for the refresh token.
     * - $parameters["encryption_algorithm"] - the encryption algorithm used for signing. The following
     * algorithms are supported: HS256, HS384, HS512, RS256, RS384, RS512.
     * - $parameters["public_key"] - location of the public key file. Required for the algorithms: RS256, RS384, RS512.
     * - $parameters["private_key"] - location of the private key file. Required for the algorithms: RS256, RS384, RS512.
     * - $parameters["pass_phrase"] - the pass phrase for the private key if necessary.
     * - $parameters["token_storage"] - the object implementing the interface {@see \OAuth2\Interfaces\ITokenStorage}. It is used for storing and
     * validating of the stored tokens.
     *
     * - $parameters["user_authenticator"] - the object implementing the interface {@see \OAuth2\Interfaces\IUserAuthenticator}. It is used for authentication
     * of the user upon his credentials before generation of the tokens.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     *
     * @see \OAuth2\Interfaces\ITokenStorage
     * @see \OAuth2\Interfaces\IUserAuthenticator
     *
     * @author Oleg Schildt
     */
    public function init($parameters)
    {
        if (!empty($parameters["access_token_ttl_minutes"])) {
            $this->access_token_ttl_minutes = $parameters["access_token_ttl_minutes"];
        }

        if (!empty($parameters["refresh_token_ttl_days"])) {
            $this->refresh_token_ttl_days = $parameters["refresh_token_ttl_days"];
        }

        if (!empty($parameters["token_storage"])) {
            $this->token_storage = $parameters["token_storage"];
        }

        if (!empty($parameters["user_authenticator"])) {
            $this->user_authenticator = $parameters["user_authenticator"];
        }

        if (!empty($parameters["encryption_algorithm"])) {
            $this->encryption_algorithm = $parameters["encryption_algorithm"];
        }

        if (!empty($parameters["secret_key"])) {
            $this->secret_key = $parameters["secret_key"];
        }

        if (!empty($parameters["public_key"])) {
            $this->public_key = $parameters["public_key"];
        }

        if (!empty($parameters["private_key"])) {
            $this->private_key = $parameters["private_key"];
        }

        if (!empty($parameters["pass_phrase"])) {
            $this->pass_phrase = $parameters["pass_phrase"];
        }

        $this->validateParameters();
    }

    /**
     * Authenticates the user based on the specified credentials and writes the response.
     *
     * @param array $credentials
     * The credentials for the authentication. The expected credentials are:
     *
     * - $credentials["client_id"] - id of the client (device token etc.).
     * - $credentials["user_login"] - the user login.
     * - $credentials["user_password"] - the user password.
     *
     * @param array &$response
     * The response upon successful authentication. The expected properties are:
     *
     * - $response["user_id"] - id of the user.
     * - $response["client_id"] - id of the client (device token etc.).
     * - $response["access_token"] - access token generated upon successful authentication.
     * - $response["access_token_expire"] - expiration time of the access token.
     * - $response["refresh_token"] - refresh token generated upon successful authentication.
     * - $response["refresh_token_expire"] - expiration time of the refresh token.
     * - $response["last_activity"] - last activity time of the user of this token.
     * - $response["jwt_access_token"] - jwt access token generated upon successful authentication. JWT access
     * token is the access token encoded and signed by the JWT standard approach.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the private key is invalid.
     * - if ssl signing fails due to system errors.
     * - if the token storage fails to save the token record.
     *
     * @throws \OAuth2\InvalidCredentialsException
     * It might throw the InvalidCredentialsException if the authentication fails.
     *
     * @throws \OAuth2\AuthSystemException
     * It might throw the AuthSystemException if some system error occurs.
     *
     * @throws \OAuth2\MissingParametersException
     * It might throw the MissingParametersException if any required paramters are empty.
     *
     * @uses OAuthManager::createTokenRecord()
     *
     * @author Oleg Schildt
     */
    public function authenticateUser($credentials, &$response)
    {
        if (empty($credentials["client_id"])) {
            throw new MissingParametersException("The client id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        $this->createTokenRecord($this->user_authenticator->authenticateUser($credentials), $credentials["client_id"], $response);
    }

    /**
     * Refreshes the access and refresh tokens by using the valid refresh token.
     *
     * @param string $refresh_token
     * The refresh token generated upon successful authentication.
     *
     * @param string $user_id
     * The user id for which the refresh token was issued.
     *
     * @param string $client_id
     * The client id for which the refresh token was issued.
     *
     * @param array &$response
     * The response upon successful refresh. The expected properties are:
     *
     * - $response["user_id"] - id of the user.
     * - $response["client_id"] - id of the client (device token etc.).
     * - $response["access_token"] - access token generated upon successful authentication.
     * - $response["access_token_expire"] - expiration time of the access token.
     * - $response["refresh_token"] - refresh token generated upon successful authentication.
     * - $response["refresh_token_expire"] - expiration time of the refresh token.
     * - $response["last_activity"] - last activity time of the user of this token.
     * - $response["jwt_access_token"] - jwt access token generated upon successful authentication. JWT access
     * token is the access token encoded and signed by the JWT standard approach.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the private key is invalid.
     * - if ssl signing fails due to system errors.
     * - if the token storage fails to verify the token record.
     * - if the token storage fails to save the token record.
     *
     * @throws \OAuth2\InvalidTokenException
     * It might throw the InvalidTokenException if the refresh token is invalid or expired.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the refresh token is expired.
     *
     * @throws \OAuth2\AuthSystemException
     * It might throw the AuthSystemException if some system error occurs.
     *
     * @throws \OAuth2\MissingParametersException
     * It might throw the MissingParametersException if any required paramters are empty.
     *
     * @uses OAuthManager::createTokenRecord()
     * @uses OAuthManager::verifyRefreshToken()
     *
     * @author Oleg Schildt
     */
    public function refreshTokens($refresh_token, $user_id, $client_id, &$response)
    {
        $this->verifyRefreshToken($refresh_token, $user_id, $client_id);

        $this->createTokenRecord($user_id, $client_id, $response);
    }

    /**
     * Verifies the jwt access token.
     *
     * @param string $jwt_access_token
     * The jwt access token generated upon successful authentication.
     *
     * @param boolean $check_on_server
     * This flag defines whether only the signatire should be checked or also the
     * authentication server should be asked.
     *
     * @return array|false
     * Returns the payload array on successful verification, otherwise false.
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the public key is invalid.
     * - if the ssl verification cannot be performed due to system errors.
     * - if the token storage fails to verify the token record.
     *
     * @throws \OAuth2\InvalidTokenException
     * It might throw the InvalidTokenException if the jwt access token is invalid.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt access token is expired.
     *
     * @throws \OAuth2\AuthSystemException
     * It might throw the AuthSystemException if some system error occurs.
     *
     * @throws \OAuth2\MissingParametersException
     * It might throw the MissingParametersException if any required paramters are empty.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::loadTokenRecord()
     *
     * @author Oleg Schildt
     */
    public function verifyJwtAccessToken($jwt_access_token, $check_on_server = true)
    {
        if (empty($jwt_access_token)) {
            throw new MissingParametersException("The access token is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        $payload = $this->getJwtPayload($jwt_access_token);

        if (empty($payload)) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload is empty!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (empty($payload["access_token"])) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload does not have the property 'access_token'!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (empty($payload["user_id"])) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload does not have the property 'user_id'!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (empty($payload["client_id"])) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload does not have the property 'client_id'!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (empty($payload["access_token_expire"])) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload does not have the property 'access_token_expire'!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (time() > $payload["access_token_expire"]) {
            throw new TokenExpiredException("The access token is expired!", "token_expired", "", [], "Expired on " . date("Y-m-d H:i:s", $payload["access_token_expire"]));
        }

        if (!$check_on_server) {
            return $payload;
        }

        $this->token_storage->verifyAccessToken($payload["access_token"], $payload["user_id"], $payload["client_id"]);

        return $payload;
    }

    /**
     * Verifies the refresh token.
     *
     * @param string $refresh_token
     * The refresh token to be verified.
     *
     * @param string $user_id
     * The user id for which the refresh token was issued.
     *
     * @param string $client_id
     * The client id for which the refresh token was issued.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the refresh token is invalid.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt access token is expired.
     *
     * @throws \OAuth2\AuthSystemException
     * It might throw the AuthSystemException if some system error occurs.
     *
     * @throws \OAuth2\MissingParametersException
     * It should throw the MissingParametersException if any required parameters are empty.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::loadTokenRecord()
     *
     * @author Oleg Schildt
     */
    public function verifyRefreshToken($refresh_token, $user_id, $client_id)
    {
        if (empty($user_id)) {
            throw new MissingParametersException("The user id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        if (empty($client_id)) {
            throw new MissingParametersException("The client id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        if (empty($refresh_token)) {
            throw new MissingParametersException("The refresh token is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        $this->token_storage->verifyRefreshToken($refresh_token, $user_id, $client_id);
    }

    /**
     * Invalidates all token records for the user.
     *
     * The invalidation by the user id is asserted by a valid client id and
     * a valid refresh token. If the refresh token is expired, the invalidation
     * can be done only after authentication.
     *
     * The invalidation is done by using {@see \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()} with the key 'user_id'.
     *
     * @param string $user_id
     * The user id for which the refresh token was issued.
     *
     * @param string $client_id
     * The client id for which the refresh token was issued.
     *
     * @param string $refresh_token
     * The refresh token generated upon successful authentication.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if the token storage fails to verify the token record.
     * - if the token storage fails to delete the token record.
     *
     * @throws \OAuth2\InvalidTokenException
     * It might throw the InvalidTokenException if the refresh token is invalid or expired.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt refresh token is expired.
     *
     * @throws \OAuth2\AuthSystemException
     * It might throw the AuthSystemException if some system error occurs.
     *
     * @throws \OAuth2\MissingParametersException
     * It might throw the MissingParametersException if any required paramters are empty.
     *
     * @uses OAuthManager::verifyRefreshToken()
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateUser($user_id, $client_id, $refresh_token)
    {
        if (empty($user_id)) {
            throw new MissingParametersException("The user id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        if (empty($client_id)) {
            throw new MissingParametersException("The client id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        if (empty($refresh_token)) {
            throw new MissingParametersException("The refresh token is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        $this->verifyRefreshToken($refresh_token, $user_id, $client_id);

        $this->token_storage->deleteTokenRecordByKey("user_id", $user_id);
    }

    /**
     * Invalidates all token records for the client.
     *
     * The invalidation by the client id is asserted by a valid client id and
     * a valid refresh token. If the refresh token is expired, the invalidation
     * can be done only after authentication.
     *
     * The invalidation is done by using {@see \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()} with the key 'client_id'.
     *
     * @param string $user_id
     * The user id for which the refresh token was issued.
     *
     * @param string $client_id
     * The client id for which the refresh token was issued.
     *
     * @param string $refresh_token
     * The refresh token generated upon successful authentication.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if the token storage fails to verify the token record.
     * - if the token storage fails to delete the token record.
     *
     * @throws \OAuth2\InvalidTokenException
     * It might throw the InvalidTokenException if the refresh token is invalid or expired.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt refresh token is expired.
     *
     * @throws \OAuth2\AuthSystemException
     * It might throw the AuthSystemException if some system error occurs.
     *
     * @throws \OAuth2\MissingParametersException
     * It might throw the MissingParametersException if any required paramters are empty.
     *
     * @uses OAuthManager::verifyRefreshToken()
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateClient($user_id, $client_id, $refresh_token)
    {
        if (empty($user_id)) {
            throw new MissingParametersException("The user id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        if (empty($client_id)) {
            throw new MissingParametersException("The client id is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        if (empty($refresh_token)) {
            throw new MissingParametersException("The refresh token is not specified!", SmartException::ERR_CODE_MISSING_REQUEST_DATA);
        }

        $this->verifyRefreshToken($refresh_token, $user_id, $client_id);

        $this->token_storage->deleteTokenRecordByKey("client_id", $client_id);
    }

    /**
     * Invalidates the token record for the jwt access token.
     *
     * The invalidation is done by using {@see \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()} with the key 'access_token'.
     *
     * The origin access token is extracted from the jwt payload.
     *
     * @param string $jwt_access_token
     * The jwt access token generated upon successful authentication.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any errors:
     *
     * - if any required initialization parameters are empty.
     * - if any initialization parameters are invalid.
     * - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - if the public key is invalid.
     * - if the ssl verification cannot be performed due to system errors.
     * - if the token storage fails to delete the token record.
     *
     * @throws \OAuth2\InvalidTokenException
     * It might throw the InvalidTokenException if the jwt access token is invalid.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateJwtAccessToken($jwt_access_token)
    {
        $payload = $this->getJwtPayload($jwt_access_token, true);

        if (empty($payload)) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload is empty!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        if (empty($payload["access_token"])) {
            throw new InvalidTokenException("The jwt access token is invalid, the payload does not have the property 'access_token'!", SmartException::ERR_CODE_INVALID_REQUEST_DATA);
        }

        $this->token_storage->deleteTokenRecordByKey("access_token", $payload["access_token"]);
    }

    /**
     * Invalidates all token records for the refresh token.
     *
     * The invalidation is done by using {@see \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()} with the key 'refresh_token'.
     *
     * @param string $refresh_token
     * The refresh token generated upon successful authentication.
     *
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors:
     *
     * - if the token storage fails to delete the token record.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the refresh token is invalid.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateRefreshToken($refresh_token)
    {
        $this->token_storage->deleteTokenRecordByKey("refresh_token", $refresh_token);
    }
}