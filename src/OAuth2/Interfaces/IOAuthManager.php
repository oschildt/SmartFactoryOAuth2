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
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors.
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
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidCredentialsException
     * It should throw the InvalidCredentialsException if the authentication fails.
     *
     * @throws \OAuth2\MissingParametersException
     * It should throw the MissingParametersException if any required paramters are empty.
     *
     * @author Oleg Schildt
     */
    public function authenticateUser($credentials, &$response);
    
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
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the refresh token is invalid.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the refresh token is expired.
     *
     * @throws \OAuth2\MissingParametersException
     * It should throw the MissingParametersException if some required paramters are empty.
     *
     * @author Oleg Schildt
     */
    public function refreshTokens($refresh_token, $user_id, $client_id, &$response);
    
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
     * The method should return the payload array on successful verification, otherwise false.
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the access token is invalid.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt access token is expired.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt access token is expired.
     *
     * @author Oleg Schildt
     */
    public function verifyJwtAccessToken($jwt_access_token, $check_on_server = true);
    
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
     * It might throw the TokenExpiredException if the refresh token is expired.
     *
     * @throws \OAuth2\MissingParametersException
     * It should throw the MissingParametersException if any required paramters are empty.
     *
     * @author Oleg Schildt
     */
    public function verifyRefreshToken($refresh_token, $user_id, $client_id);
    
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
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the refresh token is invalid.
     *
     * @throws \OAuth2\TokenExpiredException
     * It might throw the TokenExpiredException if the jwt refresh token is expired.
     *
     * @throws \OAuth2\MissingParametersException
     * It should throw the MissingParametersException if some required paramters are empty.
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
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the refresh token is invalid.
     *
     * @throws \OAuth2\MissingParametersException
     * It should throw the MissingParametersException if some required paramters are empty.
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
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the access token is invalid.
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
     * @return void
     *
     * @throws \Exception
     * It might throw an exception in the case of any system errors.
     *
     * @throws \OAuth2\InvalidTokenException
     * It should throw the InvalidTokenException if the refresh token is invalid.
     *
     * @author Oleg Schildt
     */
    public function invalidateRefreshToken($refresh_token);
} // IOAuthManager
