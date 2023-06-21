<?php
/**
 * This file contains the implementation of the MissingParametersException.
 *
 * @author Oleg Schildt
 */

namespace OAuth2;

use SmartFactory\SmartException;

/**
 * Class for the exception MissingParametersException.
 *
 * @author Oleg Schildt
 */
class MissingParametersException extends SmartException
{
    /**
     * Constructor.
     *
     * @param string $message
     * Error message.
     *
     * @param string $error_code
     * Error code.
     *
     * Since the error texts can be localized, the unique code of the error might be important fo using
     * in comparison.
     *
     * @param string $error_element
     * Error element.
     *
     * @param array $error_details
     * The details might be useful if the message translations are provided on the client, not
     * on the server, and the message should contain some details that may vary from case to case.
     * In that case, the servers return the message id instead of final text and the details, the client
     * uses the message id, gets the final translated text and substitutes the parameters through the details.
     *
     * @param string $technical_info
     * Additional technical infromation. It can be used if it is a programming error and displayed only if the debug mode is active.
     *
     * @author Oleg Schildt
     */
    public function __construct($message, $error_code = SmartException::ERR_CODE_SYSTEM_ERROR, $error_element = "", $error_details = [], $technical_info = "")
    {
        parent::__construct($message, $error_code, $error_element, $error_details, $technical_info);
    }
}