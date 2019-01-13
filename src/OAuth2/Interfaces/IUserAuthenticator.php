<?php
/**
 * This file contains the declaration of the interface IUserAuthenticator for authentication
 * of the user upon his credentials before generation of the tokens.
 *
 * @author Oleg Schildt
 */

namespace OAuth2\Interfaces;

use SmartFactory\Interfaces\IInitable;

/**
 * Interface for authentication
 * of the user upon his credentials before generation of the tokens.
 *
 * @author Oleg Schildt
 */
interface IUserAuthenticator extends IInitable
{
    /**
     * Authenticates the user based on the specified credentials.
     *
     * @param array $credentials
     * The credentials may vary depending on implementation.
     *
     * @return boolean
     * The method should return the user id upon success, otherwise false.
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
    public function authenticateUser($credentials);
}