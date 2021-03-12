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

use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\helpers\StringHelper;
use craft\helpers\ArrayHelper;
use structureit\craftcognitoauth\CraftCognitoAuth;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Token;
use DateTime;

/**
 * @author    Mike Pierce
 * @package   CraftCognitoAuth
 * @since     0.1.0
 */
class JWT extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Gets the access token in the query parameters. Returns false if no token is found.
     * @return string|false
     */
    public function getJWTFromRequest()
    {
        if (isset(Craft::$app->request->queryParams['jwt']))
            return Craft::$app->request->queryParams['jwt'];
        else
            return false;
    }

    /**
     * Parses and verifies the access token string
     *
     * @param string $accessToken
     * @return Token|false
     */
    public function parseAndVerifyJWT(string $accessToken)
    {
        $token = $this->parseJWT($accessToken);

        if ($token && $this->verifyJWT($token)) {
            return $token;
        }

        return false;
    }

    /**
     * Parses the access token string and returns a Token if it can be parsed
     *
     * @param string $accessToken
     * @return Token|false
     */
    public function parseJWT(string $accessToken)
    {
        if (count(explode('.', $accessToken)) === 3) {
            $token = (new Parser())->parse((string) $accessToken);

            return $token;
        }

        return false;
    }

    /**
     * Verifies the access token
     *
     * @param Token $token
     * @return boolean
     */
    public function verifyJWT(Token $token)
    {
        // provide explicit DateTimeInterface since lcobucci plugin update now throws errors for an optional param
        $now = new DateTime();
        // do nothing if token has expired
        if ($token->isExpired($now))
            return false;

        // check correct claims
        if (!$token->hasClaim('email') || !$token->getClaim('email_verified'))
            return false;
        $expectedAudience = Craft::parseEnv(CraftCognitoAuth::getInstance()->getSettings()->userPoolAppID);
        if (!$token->hasClaim('aud') || $token->getClaim('aud') !== $expectedAudience)
            return false;
        if (!$token->hasClaim('token_use') || $token->getClaim('token_use') !== 'id')
            return false;
        $expectedIssuer = 'https://cognito-idp.' . Craft::parseEnv(CraftCognitoAuth::getInstance()->getSettings()->userPoolRegion);
        $expectedIssuer .= '.amazonaws.com/' . Craft::parseEnv(CraftCognitoAuth::getInstance()->getSettings()->userPoolID);
        if (!$token->hasClaim('iss') || $token->getClaim('iss') !== $expectedIssuer)
            return false;

        // get JWKSet from Cognito
        $JWKS = CraftCognitoAuth::$plugin->CognitoJWK->getCognitoJWKS();
        if (!$JWKS)
            return false;
        // Choose the correct one that matches the token's KeyID
        $JWK = CraftCognitoAuth::$plugin->CognitoJWK->pickJWK($JWKS, $token->getHeader('kid', ''));
        if (!$JWK)
            return false;
        // Convert to PEM Certificate string
        $secretKey = CraftCognitoAuth::$plugin->CognitoJWK->JWKtoKey($JWK);

        // Attempt to verify the token
        $verify = $token->verify((new RsaSha256()), $secretKey);
        return $verify;
    }

    /**
     * Gets the Craft user associated with the access token
     *
     * @param Token $token
     * @return User|false
     */
    public function getUserByJWT(Token $token)
    {
        if ($this->verifyJWT($token)) {
            // Derive the username & email from the subject in the token
            $email = $token->getClaim('email', '');
            $userName = $token->getClaim('cognito:username', '');

            // Look for the user with email
            $user = Craft::$app->users->getUserByUsernameOrEmail($email);
            // If no user is found, look for the user by username
            if (!$user)
                $user = Craft::$app->users->getUserByUsernameOrEmail($userName);

            if ($user)
                return $user;
        }

        return false;
    }

    /**
     * Checks all the settings to determine if a new user should be created
     *
     * @return boolean
     */
    public function shouldAutoCreateUser()
    {
        if (CraftCognitoAuth::getInstance()->getSettings()->autoCreateUser) {
            if (Craft::$app->getProjectConfig()->get('users.allowPublicRegistration')) {
                return true;
            } else {
                return CraftCognitoAuth::getInstance()->getSettings()->autoCreateUserWhenPublicRegistrationDisabled;
            }
        } else {
            return false;
        }
    }

    /**
     * Creates a Craft user according to the provided JWT. Returns false if creating user failed
     *
     * @param Token $token
     * @return User|false
     */
    public function createUserByJWT(Token $token)
    {
        // Create a new user and populate with claims
        $user = new User();

        // Get email - verifyJWT() makes sure this has an email claim
        $email = $token->getClaim('email');
        // just in case:
        if (!$email)
            return false;

        // Set username and email
        $user->email = $email;
        $user->username = $token->getClaim('cognito:username', $email);

        // These are optional, so pass empty string as the default
        $user->firstName = $token->getClaim('given_name', '');
        $user->lastName = $token->getClaim('family_name', '');

        // Attempt to save the user
        $success = Craft::$app->getElements()->saveElement($user);

        // If user saved ok...
        if ($success && $user->id) {
            // Assign the user to the default public group
            Craft::$app->getUsers()->assignUserToDefaultGroup($user);

            // Assign user to group selected in settings
            $groupid = CraftCognitoAuth::getInstance()->getSettings()->newUserGroup;
            if (isset($groupid) && $groupid) {
                Craft::$app->getUsers()->assignUserToGroups($user->id, [$groupid]);
            }

            // Look for a picture in the claim
            $picture = $token->hasClaim('picture') ? $token->getClaim('picture') : false;
            if ($picture) {
                // Create a guzzel client
                $guzzle = Craft::createGuzzleClient();

                // Attempt to fetch the image
                $imageUpload = $guzzle->get($picture);

                // Derive the file extension from the content type
                $ext = $this->mime2ext($imageUpload->getHeader('Content-Type'));

                // Make a filename from the username, and add some randomness
                $fileName = $user->username . StringHelper::randomString() . '.' . $ext;
                $tempFile = Craft::$app->path->getTempAssetUploadsPath() . '/' . $fileName;

                // Fetch it again, this time saving it to a temp file
                $imageUpload = $guzzle->get($picture, ['save_to' => $tempFile]);

                // Save the tempfile to the user’s account as profile image
                Craft::$app->getUsers()->saveUserPhoto($tempFile, $user, $fileName);
            }

            return $user;
        } else {
            return false;
        }
    }

    /**
     * Converts a mime string to an extension string. Returns false if no mimetype found
     *
     * @param string|array $mime
     * @return string|false
     */
    public function mime2ext($mime)
    {
        $mime = ArrayHelper::isTraversable($mime) ? ArrayHelper::firstValue($mime) : $mime;

        $mime_map = [
            'video/3gpp2' => '3g2',
            'video/3gp' => '3gp',
            'video/3gpp' => '3gp',
            'application/x-compressed' => '7zip',
            'audio/x-acc' => 'aac',
            'audio/ac3' => 'ac3',
            'application/postscript' => 'ai',
            'audio/x-aiff' => 'aif',
            'audio/aiff' => 'aif',
            'audio/x-au' => 'au',
            'video/x-msvideo' => 'avi',
            'video/msvideo' => 'avi',
            'video/avi' => 'avi',
            'application/x-troff-msvideo' => 'avi',
            'application/macbinary' => 'bin',
            'application/mac-binary' => 'bin',
            'application/x-binary' => 'bin',
            'application/x-macbinary' => 'bin',
            'image/bmp' => 'bmp',
            'image/x-bmp' => 'bmp',
            'image/x-bitmap' => 'bmp',
            'image/x-xbitmap' => 'bmp',
            'image/x-win-bitmap' => 'bmp',
            'image/x-windows-bmp' => 'bmp',
            'image/ms-bmp' => 'bmp',
            'image/x-ms-bmp' => 'bmp',
            'application/bmp' => 'bmp',
            'application/x-bmp' => 'bmp',
            'application/x-win-bitmap' => 'bmp',
            'application/cdr' => 'cdr',
            'application/coreldraw' => 'cdr',
            'application/x-cdr' => 'cdr',
            'application/x-coreldraw' => 'cdr',
            'image/cdr' => 'cdr',
            'image/x-cdr' => 'cdr',
            'zz-application/zz-winassoc-cdr' => 'cdr',
            'application/mac-compactpro' => 'cpt',
            'application/pkix-crl' => 'crl',
            'application/pkcs-crl' => 'crl',
            'application/x-x509-ca-cert' => 'crt',
            'application/pkix-cert' => 'crt',
            'text/css' => 'css',
            'text/x-comma-separated-values' => 'csv',
            'text/comma-separated-values' => 'csv',
            'application/vnd.msexcel' => 'csv',
            'application/x-director' => 'dcr',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
            'application/x-dvi' => 'dvi',
            'message/rfc822' => 'eml',
            'application/x-msdownload' => 'exe',
            'video/x-f4v' => 'f4v',
            'audio/x-flac' => 'flac',
            'video/x-flv' => 'flv',
            'image/gif' => 'gif',
            'application/gpg-keys' => 'gpg',
            'application/x-gtar' => 'gtar',
            'application/x-gzip' => 'gzip',
            'application/mac-binhex40' => 'hqx',
            'application/mac-binhex' => 'hqx',
            'application/x-binhex40' => 'hqx',
            'application/x-mac-binhex40' => 'hqx',
            'text/html' => 'html',
            'image/x-icon' => 'ico',
            'image/x-ico' => 'ico',
            'image/vnd.microsoft.icon' => 'ico',
            'text/calendar' => 'ics',
            'application/java-archive' => 'jar',
            'application/x-java-application' => 'jar',
            'application/x-jar' => 'jar',
            'image/jp2' => 'jp2',
            'video/mj2' => 'jp2',
            'image/jpx' => 'jp2',
            'image/jpm' => 'jp2',
            'image/jpeg' => 'jpeg',
            'image/pjpeg' => 'jpeg',
            'application/x-javascript' => 'js',
            'application/json' => 'json',
            'text/json' => 'json',
            'application/vnd.google-earth.kml+xml' => 'kml',
            'application/vnd.google-earth.kmz' => 'kmz',
            'text/x-log' => 'log',
            'audio/x-m4a' => 'm4a',
            'application/vnd.mpegurl' => 'm4u',
            'audio/midi' => 'mid',
            'application/vnd.mif' => 'mif',
            'video/quicktime' => 'mov',
            'video/x-sgi-movie' => 'movie',
            'audio/mpeg' => 'mp3',
            'audio/mpg' => 'mp3',
            'audio/mpeg3' => 'mp3',
            'audio/mp3' => 'mp3',
            'video/mp4' => 'mp4',
            'video/mpeg' => 'mpeg',
            'application/oda' => 'oda',
            'audio/ogg' => 'ogg',
            'video/ogg' => 'ogg',
            'application/ogg' => 'ogg',
            'application/x-pkcs10' => 'p10',
            'application/pkcs10' => 'p10',
            'application/x-pkcs12' => 'p12',
            'application/x-pkcs7-signature' => 'p7a',
            'application/pkcs7-mime' => 'p7c',
            'application/x-pkcs7-mime' => 'p7c',
            'application/x-pkcs7-certreqresp' => 'p7r',
            'application/pkcs7-signature' => 'p7s',
            'application/pdf' => 'pdf',
            'application/octet-stream' => 'pdf',
            'application/x-x509-user-cert' => 'pem',
            'application/x-pem-file' => 'pem',
            'application/pgp' => 'pgp',
            'application/x-httpd-php' => 'php',
            'application/php' => 'php',
            'application/x-php' => 'php',
            'text/php' => 'php',
            'text/x-php' => 'php',
            'application/x-httpd-php-source' => 'php',
            'image/png' => 'png',
            'image/x-png' => 'png',
            'application/powerpoint' => 'ppt',
            'application/vnd.ms-powerpoint' => 'ppt',
            'application/vnd.ms-office' => 'ppt',
            'application/msword' => 'doc',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
            'application/x-photoshop' => 'psd',
            'image/vnd.adobe.photoshop' => 'psd',
            'audio/x-realaudio' => 'ra',
            'audio/x-pn-realaudio' => 'ram',
            'application/x-rar' => 'rar',
            'application/rar' => 'rar',
            'application/x-rar-compressed' => 'rar',
            'audio/x-pn-realaudio-plugin' => 'rpm',
            'application/x-pkcs7' => 'rsa',
            'text/rtf' => 'rtf',
            'text/richtext' => 'rtx',
            'video/vnd.rn-realvideo' => 'rv',
            'application/x-stuffit' => 'sit',
            'application/smil' => 'smil',
            'text/srt' => 'srt',
            'image/svg+xml' => 'svg',
            'application/x-shockwave-flash' => 'swf',
            'application/x-tar' => 'tar',
            'application/x-gzip-compressed' => 'tgz',
            'image/tiff' => 'tiff',
            'text/plain' => 'txt',
            'text/x-vcard' => 'vcf',
            'application/videolan' => 'vlc',
            'text/vtt' => 'vtt',
            'audio/x-wav' => 'wav',
            'audio/wave' => 'wav',
            'audio/wav' => 'wav',
            'application/wbxml' => 'wbxml',
            'video/webm' => 'webm',
            'audio/x-ms-wma' => 'wma',
            'application/wmlc' => 'wmlc',
            'video/x-ms-wmv' => 'wmv',
            'video/x-ms-asf' => 'wmv',
            'application/xhtml+xml' => 'xhtml',
            'application/excel' => 'xl',
            'application/msexcel' => 'xls',
            'application/x-msexcel' => 'xls',
            'application/x-ms-excel' => 'xls',
            'application/x-excel' => 'xls',
            'application/x-dos_ms_excel' => 'xls',
            'application/xls' => 'xls',
            'application/x-xls' => 'xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
            'application/vnd.ms-excel' => 'xlsx',
            'application/xml' => 'xml',
            'text/xml' => 'xml',
            'text/xsl' => 'xsl',
            'application/xspf+xml' => 'xspf',
            'application/x-compress' => 'z',
            'application/x-zip' => 'zip',
            'application/zip' => 'zip',
            'application/x-zip-compressed' => 'zip',
            'application/s-compressed' => 'zip',
            'multipart/x-zip' => 'zip',
            'text/x-scriptzsh' => 'zsh',
        ];

        return isset($mime_map[$mime]) === true ? $mime_map[$mime] : false;
    }
}
