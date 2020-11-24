<?php
/**
 * This file contains the mapping of the implementing classes to the interfaces.
 *
 * @author Oleg Schildt
 */

namespace OAuth2;

use SmartFactory\ObjectFactory;

use OAuth2\Interfaces\IOAuthManager;

//-------------------------------------------------------------------
// Class binding
//-------------------------------------------------------------------
ObjectFactory::bindClass(IOAuthManager::class, OAuthManager::class);
//-------------------------------------------------------------------
