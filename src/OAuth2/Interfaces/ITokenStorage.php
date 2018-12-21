<?php
/**
 * This file contains the declaration of the interface ITokenStorage for storing and validating of the stored tokens.
 *
 * @author Oleg Schildt
 */

namespace OAuth2\Interfaces;

use SmartFactory\Interfaces\IInitable;

/**
 * Interface for storing and validating of the stored tokens. It can be implemnted for a database or
 * for a cache solution like Redis.
 *
 * @author Oleg Schildt
 */
interface ITokenStorage extends IInitable
{
    /**
     * Saves the token record.
     *
     * It is reccomnended to look for an existing record by user_id and client_id, and if it exists,
     * it should be overwritten.
     *
     * @param array $token_record
     * The token record may vary depending on implementation. The expected parameters are:
     *
     * - $token_record["user_id"] - id of the user.
     *
     * - $token_record["client_id"] - id of the client (device token etc.).
     *
     * - $token_record["access_token"] - access token generated upon successful authentication.
     *
     * - $token_record["refresh_token"] - refresh token generated upon successful authentication.
     *
     * - $token_record["access_token_ttl"] - time to live in seconds for the access token.
     *
     * - $token_record["refresh_token_ttl"] - time to live in seconds for the refresh token.
     *
     * @return boolean
     * The method should return true upon successful save operation, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function saveTokenRecord(&$token_record);
    
    /**
     * Deletes the token record by a key.
     *
     * @param string $key
     * The name of the key, by which the record should be located and deleted. The possible keys are:
     *
     * - 'user_id' - id of the user.
     *
     * - 'client_id' - id of the client (device token etc.).
     *
     * - 'access_token' - access token generated upon successful authentication.
     *
     * - 'refresh_token' - refresh token generated upon successful authentication.
     *
     * @param string $value
     * The vale of the key, by which the record should be located and deleted.
     *
     * @return boolean
     * The method should return true upon successful deletion, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors. Possible codes are:
     *
     * - user_id_does_not_exist - no records found with this user id
     * - client_id_does_not_exist - no records found with this client id
     * - access_token_does_not_exist - no records found with this access token
     * - refresh_token_does_not_exist - no records found with this refresh
     * - ivalid_data_error - if some input data is ivalid
     *
     * @used_by IOAuthManager::invalidateUser()
     * @used_by IOAuthManager::invalidateClient()
     * @used_by IOAuthManager::invalidateJwtAccessToken()
     * @used_by IOAuthManager::invalidateRefreshToken()
     *
     * @author Oleg Schildt
     */
    public function deleteTokenRecordByKey($key, $value);
    
    /**
     * Verifies the access token.
     *
     * @param string $access_token
     * The access token to be verified.
     *
     * @param string $user_id
     * The user id for which the access token was issued.
     *
     * @param string $client_id
     * The client id for which the access token was issued.
     *
     * @return boolean
     * The method should return true upon successful verification, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function verifyAccessToken($access_token, $user_id, $client_id);
    
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
     * @return boolean
     * The method should return true upon successful verification, otherwise false.
     *
     * @throws \SmartFactory\SmartException
     * It might throw an exception in the case of any errors.
     *
     * @author Oleg Schildt
     */
    public function verifyRefreshToken($refresh_token, $user_id, $client_id);
} // ITokenStorage
