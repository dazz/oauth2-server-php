<?php

/**
*
*/
class OAuth2_Controller_AccessController implements OAuth2_Controller_AccessControllerInterface
{
    private $response;
    private $tokenType;
    private $tokenStorage;
    private $config;
    protected $logger;

    public function __construct(OAuth2_TokenTypeInterface $tokenType, OAuth2_Storage_AccessTokenInterface $tokenStorage, $config = array(), $util = null, \Symfony\Component\HttpKernel\Log\LoggerInterface $logger = null)
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;

        $this->config = array_merge(array(
            'www_realm' => 'Service',
        ), $config);

        if (is_null($util)) {
            $util = new OAuth2_Util();
        }
        $this->util = $util;

        //set the logger
        $this->logger = $logger;
        if(!$this->logger instanceof \Symfony\Component\HttpKernel\Log\LoggerInterface) {
            $this->logger = new \Symfony\Component\HttpKernel\Log\NullLogger();
        }
    }

    public function verifyAccessRequest(OAuth2_RequestInterface $request)
    {
        $token = $this->tokenType->getAccessTokenParameter($request);
        $this->response = $this->tokenType->getResponse();
        if ($token) {
            $this->logger->info('Access token is valid');
            $access_token = $this->getAccessTokenData($token, $request->query('scope'));
            return (bool) $access_token;
        }
        $this->logger->info('Access token is not valid');
        return false;
    }

    public function getAccessTokenData($token_param, $scope = null)
    {
        if (!$token_param) { // Access token was not provided
            $this->logger->info('Access token was not provided');
            $this->response = new OAuth2_Response_AuthenticationError(400, 'invalid_request', 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Get the stored token data (from the implementing subclass)
        $token = $this->tokenStorage->getAccessToken($token_param);
        if ($token === null) {
            $this->logger->info('The access token provided is invalid');
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'The access token provided is invalid', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Check we have a well formed token
        if (!isset($token["expires"]) || !isset($token["client_id"])) {
            $this->logger->info('Malformed token (missing "expires" or "client_id")');
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'Malformed token (missing "expires" or "client_id")', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Check token expiration (expires is a mandatory paramter)
        if (isset($token["expires"]) && time() > $token["expires"]) {
            $this->logger->info('The access token provided has expired');
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'The access token provided has expired', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Check scope, if provided
        // If token doesn't have a scope, it's null/empty, or it's insufficient, then throw an error
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->util->checkScope($scope, $token["scope"]))) {
            $this->logger->info('The request requires higher privileges than provided by the access token');
            $this->response = new OAuth2_Response_AuthenticationError(401, 'insufficient_scope', 'The request requires higher privileges than provided by the access token', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        $this->logger->debug('The access token can be send', $token);
        return $token;
    }

    public function getResponse()
    {
        return $this->response;
    }
}