<?php
/**
 * This file contains the declaration of the interface IOAuthManager for secure user authentication.
 *
 * @author Oleg Schildt
 */

namespace OAuth2\Interfaces;

use SmartFactory\Interfaces\IInitable;

/**
 * Interface for secure user authentication.
 *
 * @author Oleg Schildt
 */
interface IOAuthManager extends IInitable
{
    /**
     * Initializes the authentication manager with parameters. 
     *
     * @param array $parameters
     * The parameters may vary depending on implementation.
     *
     * @return boolean
     * The method should return true upon successful initialization, otherwise false.
     *
     * @author Oleg Schildt
     */
    public function init($parameters);
    
    /**
     * Authenticates the user based on the specified credentials and writes the response.
     *
     * It should use {@see \OAuth2\Interfaces\IUserAuthenticator} for the authentication.
     *
     * @param array $credentials
     * The credentials for the authentication. They may vary depending on implementation.
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
     * The method should return true upon success, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function authenticateUser($credentials, &$response);
    
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
     * The method should return true upon success, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function refreshAccessToken($refresh_token, $user_id, $client_id, &$response);
    
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
     * @param boolean $check_on_server
     * This flag defines whether only the signatire should be checked or also the
     * authentication server should be asked.
     *
     * @return boolean
     * The method should return true on successful verification, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function verifyJwtAccessToken($jwt_access_token, $user_id, $client_id, $check_on_server = true);
    
    /**
     * Invalidates all token records for the user.
     *
     * The invalidation by the user id should be asserted by a valid client id and
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
     * The method should return true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function invalidateUser($user_id, $client_id, $refresh_token);
    
    /**
     * Invalidates all token records for the client.
     *
     * The invalidation by the client id should be asserted by a valid user id and
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
     * The method should return true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function invalidateClient($user_id, $client_id, $refresh_token);
    
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
     * The method should return true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function invalidateJwtAccessToken($jwt_access_token);
    
    /**
     * Invalidates all token records for the refresh token.
     *
     * The invalidation is done by using {@see \OAuth2\Interfaces\ITokenStorage::deleteTokenRecordByKey()} with the key 'refresh_token'.
     *
     * @param string $refresh_token
     * The refresh token generated upon successful authentication.
     *
     * @return boolean
     * The method should return true on successful invalidation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function invalidateRefreshToken($refresh_token);
} // IOAuthManager
