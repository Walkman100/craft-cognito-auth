<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace structureit\craftcognitoauth\services;

use CoderCat\JWKToPEM\JWKConverter;
use Craft;
use craft\base\Component;
use structureit\craftcognitoauth\CraftCognitoAuth;
use Lcobucci\JWT\Signer\Key\InMemory;

/**
 * @author    Mike Pierce
 * @package   CraftCognitoAuth
 * @since     0.1.0
 */
class CognitoJWK extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Gets the Cognito JWKS (Json Web Key Set) associated with the User Pool configured in Settings.
     * Return type is `array[array[string]]`, but set to `array` to fix type hinting.
     *
     * @return array|false
     */
    public function getCognitoJWKS()
    {
        // get JSON string
        $wellKnownPath = 'https://cognito-idp.' . Craft::parseEnv(CraftCognitoAuth::getInstance()->getSettings()->userPoolRegion);
        $wellKnownPath .= '.amazonaws.com/' . Craft::parseEnv(CraftCognitoAuth::getInstance()->getSettings()->userPoolID) . '/.well-known/jwks.json';
        $JWKSstringArray = file_get_contents($wellKnownPath);
        if ($JWKSstringArray === false)
            return false;

        // decode and return array
        $JWKS = json_decode($JWKSstringArray, true);
        if (isset($JWKS['keys']))
            return $JWKS['keys'];
        else
            return false;
    }

    /**
     * Picks the correct JWK (Json Web Key) for the provided KeyID.
     * Returns `array[string]` on correct Key found, and `false` on no key found
     *
     * @param array[array[string]] $jwks
     * @param string $kid
     * @return array|false
     */
    public function pickJWK(array $jwks, string $kid)
    {
        foreach ($jwks as $jwk) {
            if (isset($jwk['kid']) && $jwk['kid'] === $kid)
                return $jwk;
        }
        return false;
    }

    /**
     * Converts a provided JWK array to a signing key string (PEM certificate)
     *
     * @param array[string] $jwk
     * @return string
     */
    public function JWKtoKey(array $jwk)
    {
        $jwkConverter = new JWKConverter();
        $PEM = $jwkConverter->toPEM($jwk);

        // convert to InMemory to satisfy JWT library requirements
        $PEMInMem = new InMemory($PEM);
        return $PEMInMem;
    }
}
