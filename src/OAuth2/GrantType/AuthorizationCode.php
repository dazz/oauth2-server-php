<?php

/**
*
*/
class OAuth2_GrantType_AuthorizationCode implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;

    public function __construct(OAuth2_Storage_AuthorizationCodeInterface $storage, \Symfony\Component\HttpKernel\Log\LoggerInterface $logger = null)
    {
        $this->storage = $storage;

        //set the logger
        $this->logger = $logger;
        if(!$this->logger instanceof \Symfony\Component\HttpKernel\Log\LoggerInterface) {
            $this->logger = new \Symfony\Component\HttpKernel\Log\NullLogger();
        }
    }

    public function getQuerystringIdentifier()
    {
        return 'authorization_code';
    }

    public function validateRequest($request)
    {
        if (!$request->query('code')) {
            $this->logger->info('Missing parameter: "code" is required');
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameter: "code" is required');
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        if (!$tokenData = $this->storage->getAuthorizationCode($request->query('code'))) {
            $this->logger->info('Authorization code doesn\'t exist or is invalid for the client');
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return null;
        }

        /*
         * 4.1.3 - ensure that the "redirect_uri" parameter is present if the "redirect_uri" parameter was included in the initial authorization request
         * @uri - http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1.3
         */
        if (isset($tokenData['redirect_uri']) && $tokenData['redirect_uri']) {
            if (!$request->query('redirect_uri') || urldecode($request->query('redirect_uri')) != $tokenData['redirect_uri']) {
                $this->logger->info('The redirect URI is missing or do not match", "#section-4.1.3');
                $this->response = new OAuth2_Response_Error(400, 'redirect_uri_mismatch', "The redirect URI is missing or do not match", "#section-4.1.3");
                return false;
            }
        }

        return $tokenData;
    }

    public function validateTokenData($tokenData, array $clientData)
    {
        // Check the code exists
        if ($tokenData === null || $clientData['client_id'] != $tokenData['client_id']) {
            $this->logger->info('Authorization code doesn\'t exist or is invalid for the client');
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return false;
        }

        if ($tokenData["expires"] < time()) {
            $this->logger->info('The authorization code has expired');
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "The authorization code has expired");
            return false;
        }

        // Scope is validated in the client class
        $this->logger->debug('Scope is validated in the client class');
        return true;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        $this->logger->info('Access Token is created.');
        return $accessToken->createAccessToken($clientData['client_id'], $tokenData['user_id'], $tokenData['scope']);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
