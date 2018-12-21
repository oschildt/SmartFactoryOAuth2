<?php
/**
 * This file contains the implementation of the interface IOAuthManager for secure user authentication.
 *
 * @author Oleg Schildt
 */

namespace OAuth2;

use OAuth2\Interfaces\IOAuthManager;
use OAuth2\Interfaces\ITokenStorage;
use OAuth2\Interfaces\IUserAuthenticator;


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
    protected $access_token_ttl = null;
    
    /**
     * Internal property for storing the time to live of the refresh token.
     *
     * @var string
     *
     * @author Oleg Schildt
     */
    protected $refresh_token_ttl = null;
    
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
     * @see urlSafeB64Decode()
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
     * @see urlSafeB64Encode()
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
     * @return boolean
     * Returns true if the verification was successful, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - invalid_data_error - if the public key is invalid.
     * - system_error - if the ssl verification cannot be performed due to errors.
     *
     * @uses generateRSASignature()
     *
     * @see  generateRSASignature()
     *
     * @used_by verifyJwtSignature()
     *
     * @author Oleg Schildt
     */
    protected function verifyRSASignature($input, $signature, $algorithm_id)
    {
        $this->validateParameters();
        
        $public_key = openssl_pkey_get_public("file://" . $this->public_key);
        if ($public_key === false) {
            throw new \SmartFactory\SmartException(sprintf("The public key file '%s' is not valid! Error: %s", $this->public_key, openssl_error_string()), "invalid_data_error");
        }
        
        $result = @openssl_verify($input, $signature, $public_key, $algorithm_id);
        
        if ($result == -1) {
            throw new \SmartFactory\SmartException(sprintf("Error by data verification: %s", openssl_error_string()), "system_error");
        }
        
        return $result === 1;
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
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - invalid_data_error - if the private key is invalid.
     * - system_error - if signing fails.
     *
     * @see verifyRSASignature()
     *
     * @used_by generateJwtSignature()
     *
     * @author Oleg Schildt
     */
    protected function generateRSASignature($input, $algorithm_id)
    {
        $this->validateParameters();
        
        $private_key = openssl_pkey_get_private("file://" . $this->private_key, $this->pass_phrase);
        if ($private_key === false) {
            throw new \SmartFactory\SmartException(sprintf("The private key file '%s' or the pass phrase is not valid! Error: %s", $this->private_key, openssl_error_string()), "invalid_data_error");
        }
        
        $signature = "";
        if (!openssl_sign($input, $signature, $private_key, $algorithm_id)) {
            throw new \SmartFactory\SmartException(sprintf("Error by signing data: %s", openssl_error_string()), "system_error");
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
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - invalid_data_error - if the private key is invalid.
     * - system_error - if signing fails.
     *
     * @uses generateRSASignature()
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
                throw new \SmartFactory\SmartException(sprintf("Unsupported or invalid signing algorithm '%s'.", $this->encryption_algorithm), "invalid_data_error");
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
     * @return boolean
     * Returns true if the verification was successful, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - invalid_data_error - if the public key is invalid.
     * - system_error - if the ssl verification cannot be performed due to errors.
     *
     * @uses verifyRSASignature()
     *
     * @author Oleg Schildt
     */
    protected function verifyJwtSignature($input, $signature)
    {
        switch ($this->encryption_algorithm) {
            case'HS256':
            case'HS384':
            case'HS512':
                return hash_equals($this->generateJwtSignature($input), $signature);
            
            case 'RS256':
                return $this->verifyRSASignature($input, $signature, OPENSSL_ALGO_SHA256);
            
            case 'RS384':
                return $this->verifyRSASignature($input, $signature, OPENSSL_ALGO_SHA384);
            
            case 'RS512':
                return $this->verifyRSASignature($input, $signature, OPENSSL_ALGO_SHA512);
            
            default:
                throw new \SmartFactory\SmartException(sprintf("Unsupported or invalid signing algorithm '%s'.", $this->encryption_algorithm), "invalid_data_error");
        }
        
        return false;
    }
    
    /**
     * Internal auxiliary function for generation of a token string.
     *
     * @return string
     * Returns the token string.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - system_error - if the system funtions for generation fail.
     *
     * @author Oleg Schildt
     */
    protected function generateToken()
    {
        try {
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
        } catch (\Exception $ex) {
            throw new \SmartFactory\SmartException($ex->getMessage(), "system_error");
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
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - invalid_data_error - if the private key is invalid.
     * - system_error - if signing fails.
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
     * @param boolean $verify
     * The flag to control whether the signature should be verified or not.
     *
     * @return array
     * Returns the extracted payload array.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - invalid_access_token - if the jwt access token is invalid.
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     * - invalid_data_error - if the public key is invalid.
     * - system_error - if the ssl verification cannot be performed due to errors.
     *
     * @author Oleg Schildt
     */
    protected function getJwtPayload($jwt_access_token, $verify = true)
    {
        if (!strpos($jwt_access_token, '.')) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        $segements = explode('.', $jwt_access_token);
        
        if (count($segements) != 3) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        list($headb64, $payloadb64, $cryptob64) = $segements;
        
        if (null === ($header = json_decode($this->urlSafeB64Decode($headb64), true))) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        if (null === $payload = json_decode($this->urlSafeB64Decode($payloadb64), true)) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        if (!$verify) {
            return $payload;
        }
        
        if (empty($header['alg'])) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        $signature = $this->urlSafeB64Decode($cryptob64);
        
        if (!in_array($header['alg'], $this->supported_algorithms)) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        
        if (!$this->verifyJwtSignature("$headb64.$payloadb64", $signature)) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        return $payload;
    }
    
    /**
     * Internal auxiliary function for validation of the parameters.
     *
     * @return boolean
     * returns true upon successful validation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     *
     * @used_by verifyRSASignature()
     * @used_by generateRSASignature()
     * @used_by init()
     *
     * @author Oleg Schildt
     */
    protected function validateParameters()
    {
        if (empty($this->access_token_ttl) || !is_numeric($this->access_token_ttl) || $this->access_token_ttl < 1) {
            throw new \SmartFactory\SmartException("The 'access_token_ttl' is not specified or invalid!", "invalid_data_error");
        }
        
        if (empty($this->refresh_token_ttl) || !is_numeric($this->refresh_token_ttl) || $this->refresh_token_ttl < 1) {
            throw new \SmartFactory\SmartException("The 'refresh_token_ttl' is not specified or invalid!", "invalid_data_error");
        }
        
        if (empty($this->token_storage)) {
            throw new \SmartFactory\SmartException("The 'token_storage' is not specified!", "missing_data_error");
        }
        
        if (!$this->token_storage instanceof ITokenStorage) {
            throw new \SmartFactory\SmartException(sprintf("The 'token_storage' does not implement the interface '%s'!", ITokenStorage::class), "invalid_data_error");
        }
        
        if (empty($this->user_authenticator)) {
            throw new \SmartFactory\SmartException("The 'user_authenticator' is not specified!", "missing_data_error");
        }
        
        if (!$this->user_authenticator instanceof IUserAuthenticator) {
            throw new \SmartFactory\SmartException(sprintf("The 'user_authenticator' does not implement the interface '%s'!", IUserAuthenticator::class), "invalid_data_error");
        }
        
        if (empty($this->encryption_algorithm)) {
            throw new \SmartFactory\SmartException("The encryption algorithm is not specified!", "missing_data_error");
        }
        
        if (!in_array($this->encryption_algorithm, $this->supported_algorithms)) {
            throw new \SmartFactory\SmartException(sprintf("The encryption algorithm %s is not supported! The suppoted algoritms are: %s", $this->encryption_algorithm, implode(", ", $this->supported_algorithms)), "invalid_data_error");
        }
        
        if (in_array($this->encryption_algorithm, ['HS256', 'HS384', 'HS512']) && empty($this->secret_key)) {
            throw new \SmartFactory\SmartException(sprintf("The encryption algorithm %s requires a secret key! Set the parameter 'secret_key'.", $this->encryption_algorithm), "missing_data_error");
        }
        
        if (in_array($this->encryption_algorithm, ['RS256', 'RS384', 'RS512']) && (empty($this->public_key) || empty($this->private_key))) {
            throw new \SmartFactory\SmartException(sprintf("The encryption algorithm %s requires a public key and a private key! Set the parameters 'public_key' and 'private_key'.", $this->encryption_algorithm));
        }
        
        if (!file_exists($this->private_key)) {
            throw new \SmartFactory\SmartException(sprintf("The private key file '%s' does not exists!", $this->private_key), "invalid_data_error");
        }
        
        if (!file_exists($this->public_key)) {
            throw new \SmartFactory\SmartException(sprintf("The public key file '%s' does not exists!", $this->public_key), "invalid_data_error");
        }
        
        return true;
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
     * @param array $response
     * The response to be filled with the user data and tokens.
     *
     * @return boolean
     * returns true upon successful creation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - system_error - if the system funtions for generation fail.
     *
     * @uses ITokenStorage::saveTokenRecord()
     *
     * @used_by authenticateUser()
     * @used_by refreshAccessToken()
     *
     * @author Oleg Schildt
     */
    protected function createTokenRecord($user_id, $client_id, &$response)
    {
        $response["user_id"] = $user_id;
        
        $response["refresh_token"] = $this->generateToken();
        $response["refresh_token_expire"] = time() + $this->refresh_token_ttl;
        
        $response["access_token"] = $this->generateToken();
        
        $payload = ["access_token" => $response["access_token"]];
        $response["jwt_access_token"] = $this->createJwtToken($payload);
        $response["access_token_expire"] = time() + $this->access_token_ttl;
        
        $response["client_id"] = $client_id;
        
        $this->token_storage->saveTokenRecord($response);
        
        // We do not want to send back the client id and access_token as plain text
        unset($response["client_id"]);
        unset($response["access_token"]);
        
        return true;
    }
    
    /**
     * Initializes the authentication manager with parameters.
     *
     * @param array $parameters
     * The parameters are:
     *
     * - $parameters["access_token_ttl"] - time to live in seconds for the access token.
     *
     * - $parameters["refresh_token_ttl"] - time to live in seconds for the refresh token.
     *
     * - $parameters["encryption_algorithm"] - the encryption algorithm used for signing. The following
     * algorithms are supported: HS256, HS384, HS512, RS256, RS384, RS512.
     *
     * - $parameters["public_key"] - location of the public key file. Required for the algorithms: RS256, RS384, RS512.
     *
     * - $parameters["private_key"] - location of the private key file. Required for the algorithms: RS256, RS384, RS512.
     *
     * - $parameters["pass_phrase"] - the pass phrase for the private key if necessary.
     *
     * - $parameters["token_storage"] - the object implementing the interface {@see \OAuth2\Interfaces\ITokenStorage}. It is used for storing and
     * validating of the stored tokens.
     *
     * - $parameters["user_authenticator"] - the object implementing the interface {@see \OAuth2\Interfaces\IUserAuthenticator}. It is used for authentication
     * of the user upon his credentials before generation of the tokens.
     *
     * @return boolean
     * returns true upon successful initialization, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     *
     * @see ITokenStorage
     * @see IUserAuthenticator
     *
     * @author Oleg Schildt
     */
    public function init($parameters)
    {
        if (!empty($parameters["access_token_ttl"])) {
            $this->access_token_ttl = $parameters["access_token_ttl"];
        }
        
        if (!empty($parameters["refresh_token_ttl"])) {
            $this->refresh_token_ttl = $parameters["refresh_token_ttl"];
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
        
        return $this->validateParameters();
    }
    
    /**
     * Authenticates the user based on the specified credentials and writes the response.
     *
     * @param array $credentials
     * The credentials for the authentication. The expected credentials are:
     *
     * - $credentials["client_id"] - id of the client (device token etc.).
     *
     * - $credentials["user_login"] - the user login.
     *
     * - $credentials["user_password"] - the user password.
     *
     * @param array $response
     * The response upon successful authentication. The expected properties are:
     *
     * - $response["user_id"] - id of the user.
     *
     * - $response["jwt_access_token"] - jwt access token generated upon successful authentication. JWT access
     * token is the access token encoded and signed by the JWT standard approach.
     *
     * - $response["refresh_token"] - refresh token generated upon successful authentication.
     *
     * - $response["access_token_ttl"] - time to live in seconds for the access token.
     *
     * - $response["refresh_token_ttl"] - time to live in seconds for the refresh token.
     *
     * @return boolean
     * Returns true upon success, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It throws the following exception strings:
     *
     * - client_id_empty - if the client id is not specified.
     * - user_login_empty - if the user login is not specified.
     * - user_password_empty - if the use password is not specified.
     * - invalid_credentials - if the credentials are invalid.
     *
     * @author Oleg Schildt
     */
    public function authenticateUser($credentials, &$response)
    {
        if (empty($credentials["client_id"])) {
            throw new \SmartFactory\SmartException("The client id is not specified!", "client_id_empty");
        }
        
        return $this->createTokenRecord($this->user_authenticator->authenticateUser($credentials), $credentials["client_id"], $response);
    }
    
    /**
     * Refreshes the access token by using the valid refresh token, if the access token is expired.
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
     * @param array $response
     * The response upon successful refresh. The expected properties are:
     *
     * - $response["user_id"] - id of the user.
     *
     * - $response["jwt_access_token"] - jwt access token generated upon successful authentication. JWT access
     * token is the access token encoded and signed by the JWT standard approach.
     *
     * - $response["refresh_token"] - refresh token generated upon successful refresh. The refresh token is also renewed!
     *
     * - $response["access_token_ttl"] - time to live in seconds for the access token.
     *
     * - $response["refresh_token_ttl"] - time to live in seconds for the refresh token.
     *
     * @return boolean
     * Returns true upon success, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It throws the following exception strings:
     *
     * - invalid_refresh_token - if the refresh token is invalid (does not exist).
     * - refresh_token_expired - if the refresh token is expired.
     *
     * @uses ITokenStorage::verifyRefreshToken()
     *
     * @author Oleg Schildt
     */
    public function refreshAccessToken($refresh_token, $user_id, $client_id, &$response)
    {
        if (!$this->token_storage->verifyRefreshToken($refresh_token, $user_id, $client_id)) {
            return false;
        }
        
        return $this->createTokenRecord($user_id, $client_id, $response);
    }
    
    /**
     * Verifies the jwt access token.
     *
     * @param string $jwt_access_token
     * The jwt access token generated upon successful authentication.
     *
     * @param string $user_id
     * The user id for which the access token was issued.
     *
     * @param string $client_id
     * The client id for which the access token was issued.
     *
     * @return boolean
     * Returns true on successful verification, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It throws the following exception strings:
     *
     * - invalid_access_token - if the access token is invalid (does not exist).
     * - access_token_expired - if the access token is expired.
     *
     * @param boolean $check_on_server
     * This flag defines whether only the signatire should be checked or also the
     * authentication server should be asked.
     *
     * @uses ITokenStorage::verifyAccessToken()
     *
     * @author Oleg Schildt
     */
    public function verifyJwtAccessToken($jwt_access_token, $user_id, $client_id, $check_on_server = true)
    {
        $payload = $this->getJwtPayload($jwt_access_token);
        
        if (empty($payload) || empty($payload["access_token"])) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        if(!$check_on_server) return true;
        
        return $this->token_storage->verifyAccessToken($payload["access_token"], $user_id, $client_id);
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
     * @return boolean
     * Returns true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - refresh_token_expired - if the refresh token is expired.
     * - invalid_refresh_token - if the refresh token is invalid.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateUser($user_id, $client_id, $refresh_token)
    {
        if (!$this->token_storage->verifyRefreshToken($refresh_token, $user_id, $client_id)) {
            return false;
        }
        
        return $this->token_storage->deleteTokenRecordByKey("user_id", $user_id);
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
     * @return boolean
     * Returns true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - refresh_token_expired - if the refresh token is expired.
     * - invalid_refresh_token - if the refresh token is invalid.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateClient($user_id, $client_id, $refresh_token)
    {
        if (!$this->token_storage->verifyRefreshToken($refresh_token, $user_id, $client_id)) {
            return false;
        }
        
        return $this->token_storage->deleteTokenRecordByKey("client_id", $client_id);
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
     * @return boolean
     * Returns true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * It might throw an exception in the case of any errors:
     *
     * - invalid_access_token - if the jwt access token is invalid.
     * - missing_data_error - if the required parameters are empty.
     * - invalid_data_error - if some parameters are invalid.
     * - invalid_data_error - if token_storage does not implement {@see \OAuth2\Interfaces\ITokenStorage}.
     * - invalid_data_error - if user_authenticator does not implement {@see \OAuth2\Interfaces\IUserAuthenticator}.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateJwtAccessToken($jwt_access_token)
    {
        $payload = $this->getJwtPayload($jwt_access_token, false);
        
        if (empty($payload) || empty($payload["access_token"])) {
            throw new \SmartFactory\SmartException("The access token is invalid!", "invalid_access_token");
        }
        
        return $this->token_storage->deleteTokenRecordByKey("access_token", $payload["access_token"]);
    }
    
    /**
     * Invalidates all token records for the refresh token.
     *
     * The invalidation is done by using {@see \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()} with the key 'refresh_token'.
     *
     * @param string $refresh_token
     * The refresh token generated upon successful authentication.
     *
     * @return boolean
     * Returns true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors:
     *
     * - invalid_data_error - if some database parameters are invalid.
     *
     * @uses \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()
     *
     * @author Oleg Schildt
     */
    public function invalidateRefreshToken($refresh_token)
    {
        return $this->token_storage->deleteTokenRecordByKey("refresh_token", $refresh_token);
    }
}