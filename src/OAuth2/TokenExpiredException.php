<?php

namespace OAuth2;

use SmartFactory\SmartException;

/**
 * Represents an access or refresh token that has reached its expiration time.
 *
 * @author Oleg Schildt
 */
class TokenExpiredException extends SmartException
{

    /**
     * Creates an authentication exception with structured diagnostics and an optional cause.
     *
     * @param string $message
     * The public error message or localization identifier.
     *
     * @param string $error_code
     * The stable string code, independent of localized text.
     *
     * @param string $error_element
     * The related request field, or an empty string.
     *
     * @param array<array-key, mixed> $error_details
     * Structured localization parameters; keys, types and nested values are preserved.
     * A server may return a message identifier and these details so the client can
     * translate the message and substitute its variable parameters.
     *
     * @param string $technical_info
     * Internal diagnostics intended only for debugging or server-side logs.
     *
     * @param ?\Throwable $previous
     * The original exception or error, or null when no underlying cause exists.
     *
     * @author Oleg Schildt
     */
    public function __construct(
        string $message,
        string $error_code = 'token_expired',
        string $error_element = "",
        array $error_details = [],
        string $technical_info = "",
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $error_code, $error_element, $error_details, $technical_info, $previous);
    } // __construct
} // TokenExpiredException
