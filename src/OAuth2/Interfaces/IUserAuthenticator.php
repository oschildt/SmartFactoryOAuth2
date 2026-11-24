<?php

namespace OAuth2\Interfaces;

use SmartFactory\Interfaces\IInitable;

/**
 * Authenticates application-specific credentials before token issuance.
 *
 * @author Oleg Schildt
 */
interface IUserAuthenticator extends IInitable
{
    /**
     * Authenticates credentials and returns the user identifier.
     * Failure is represented by an exception, never by false or a sentinel user ID.
     *
     * @param array<string, mixed> $credentials
     * Application-specific credentials; implementations must validate their types before using them.
     *
     * @return int|string
     * Returns the authenticated user identifier. Zero and the string "0" are valid identifiers;
     * strings must be nonempty UTF-8 without control characters.
     *
     * @throws \OAuth2\MissingParametersException
     * If a required credential is absent.
     *
     * @throws \OAuth2\InvalidCredentialsException
     * If credentials are malformed or do not authenticate a user.
     *
     * @throws \Exception
     * If the identity backend cannot complete authentication.
     *
     * @author Oleg Schildt
     */
    public function authenticateUser(array $credentials): int|string;
} // IUserAuthenticator
