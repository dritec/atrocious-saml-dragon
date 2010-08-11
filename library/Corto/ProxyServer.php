<?php

/**
 *
 */

class Corto_ProxyServer_Exception extends Exception
{
}

class Corto_ProxyServer
{
    const MODULE_BINDINGS   = 'Bindings';

    const TEMPLATE_SOURCE_FILESYSTEM = 'filesystem';
    const TEMPLATE_SOURCE_MEMORY     = 'memory';

    const MESSAGE_TYPE_REQUEST  = 'SAMLRequest';
    const MESSAGE_TYPE_RESPONSE = 'SAMLResponse';


    protected $_requestArray;
    protected $_responseArray;

    protected $_server;

    protected $_configs;
    protected $_entities = array(
        'current'=>array(),
        'hosted'=>array(),
        'remote'=>array(),
    );
    protected $_modules = array();
    protected $_templateSource;

    public function __construct()
    {
        $this->_server = $this;
    }

    //////// GETTERS / SETTERS /////////

    /**
     * @return Corto_Module_Bindings
     */
    public function getBindingsModule()
    {
        return $this->_getModule(self::MODULE_BINDINGS);
    }

    /**
     * @param Corto_Module_Bindings $bindingsInstance
     * @return Corto_ProxyServer
     */
    public function setBindingsModule(Corto_Module_Bindings $bindingsInstance)
    {
        return $this->_setModule(self::MODULE_BINDINGS, $bindingsInstance);
    }

    /**
     * @return Corto_Module_Services
     */
    public function getServicesModule()
    {
        return $this->_getModule(self::MODULE_SERVICES);
    }

    /**
     * @param Corto_Module_Services $servicesInstance
     * @return Corto_ProxyServer
     */
    public function setServicesModule(Corto_Module_Services $servicesInstance)
    {
        return $this->_setModule(self::MODULE_SERVICES, $servicesInstance);
    }

    /**
     * @param string $name
     * @return Corto_Module_Abstract
     */
    protected function _getModule($name)
    {
        return $this->_modules[$name];
    }

    /**
     * @param  $name
     * @param  $moduleInstance
     * @return Corto_ProxyServer
     */
    protected function _setModule($name, Corto_Module_Abstract $moduleInstance)
    {
        $this->_modules[$name] = $moduleInstance;
        return $this;
    }

    public function getConfig($name, $default = null)
    {
        if (isset($this->_configs[$name])) {
            return $this->_configs[$name];
        }
        return $default;
    }

    public function setConfigs($configs)
    {
        $this->_configs = $configs;
        return $this;
    }

    public function getCurrentEntity()
    {
        return $this->_entities['current'];
    }

    public function setCurrentEntity($entity)
    {
        $this->_entities['current'] = $entity;
        return $this;
    }

    public function setHostedEntities($entities)
    {
        $this->_entities['hosted'] = $entities;
    }

    public function getHostedEntities()
    {
        return $this->_entities['hosted'];
    }

    public function getCurrentHostedEntityUrl($serviceName = "", $remoteEntityId = "")
    {
        return $this->getHostedEntityUrl($serviceName, $this->_entities['current']['EntityCode'], $remoteEntityId);
    }

    public function getHostedEntityUrl($entityCode, $serviceName = "", $remoteEntityId = "")
    {
        $scheme = 'http';
        if (isset($_SERVER['HTTPS'])) {
            $scheme = 'https';
        }

        $host = $_SERVER['HTTP_HOST'];

        $entityPart = $entityCode;
        if ($remoteEntityId) {
            $entityPart .= '_' . md5($remoteEntityId);
        }

        if (!$serviceName) {
            return $scheme . '://' . $host . '/' . $entityPart;
        }

        return $scheme . '://' . $host . '/' . $entityPart . '/' . $serviceName;
    }

    public function getRemoteEntity($entityId)
    {
        if (isset($this->_entities['remote'][$entityId])) {
            return $this->_entities['remote'][$entityId];
        }
    }

    public function getRemoteEntities()
    {
        return $this->_entities['remote'];
    }

    public function setRemoteEntities($entities)
    {
        $this->_entities['remote'] = $entities;
    }

    public function setTemplateSource($type, $arguments)
    {
        $this->_templateSource = array(
            'type'      => $type,
            'arguments' => $arguments,
        );
        return $this;
    }

    public function getTemplateSource()
    {
        return $this->_templateSource;
    }

    //////// MAIN /////////

    public function serveRequest($uri)
    {
        $parameters = $this->_getParametersFromUri($uri);
        $this->_setCurrentEntity($parameters['EntityCode'], $parameters['RemoteIdPMd5']);

        $this->startSession();

        $this->getServicesModule()->{$parameters['ServiceName']}();

        

    // Get message and message type from binding
    // If we want requests signed OR If we want assertions signed check signing
        // If the issuer has a sharedkey defined
            // Get the raw message from either JSON Redirect or JSON Post
            // Check if the Signature equals the base64 encode of the shas of the shared key and message
        // Else if we use HTTP Redirect
            // Build the raw message from the query string
            // Verify it against the public key
        // Else if we use HTTP Post
            // Check whether either the message or the assertion verifies

    // Check whether we know the destination

    // Resolve SAMLRequest ambiguity with 'true' or '1' for isPassive and ForceAuthn.

    // If we have an encrypted assertion, decrypt it.

    // Check SAMLResponse SubjectConfirmation timings
    // Check SAMLResponse Conditions timings
    // Check SAMLResponse AuthnStatement timing
    }

    protected function _setCurrentEntity($entityCode, $remoteIdPMd5 = "")
    {
        $entityId = $this->getHostedEntityUrl($entityCode);
        $hostedEntity = array();
        if (isset($this->_entities['hosted'][$entityId])) {
            $hostedEntity = $this->_entities['hosted'][$entityId];
        }

        $hostedEntity['EntityId']   = $entityId;
        $hostedEntity['EntityCode'] = $entityCode;

        if ($remoteIdPMd5) {
            $remoteEntityIds = array_keys($this->_entities['remote']);
            foreach ($remoteEntityIds as $remoteEntityId) {
                if (md5($remoteEntityId) === $remoteIdPMd5) {
                    $hostedEntity['IdP'] = $remoteEntityId;
                    break;
                }
            }
        }

        $this->setCurrentEntity($hostedEntity);
    }

    protected function _getParametersFromUri($uri)
    {
        $parameters = array(
            'EntityCode'    => '',
            'ServiceName'   => '',
            'RemoteIdPMd5'  => '',

        );

        if ($uri) {
            // From corto.php/hostedEntity/requestedService get the hosted entity code and the requested service
            $entityCodeAndService = preg_split('/\//', $uri, 0, PREG_SPLIT_NO_EMPTY);
            if (isset($entityCodeAndService[0])) {
                // From the hosted entity name like entity name_myidp, get a hosted IDP identifier (myIdp in the example).
                $entityComponents = preg_split('/_/', $entityCodeAndService[0], 0, PREG_SPLIT_NO_EMPTY);

                $parameters['EntityCode'] = $entityComponents[0];
                if (isset($entityComponents[1])) {
                    $parameters['RemoteIdPMd5'] = $entityComponents[1];
                }
            }
            if (isset($entityCodeAndService[1])) {
                $parameters['ServiceName'] = $entityCodeAndService[1];
            }
        }

        if (!$parameters['EntityCode']) {
            $parameters['EntityCode'] = 'main';
        }
        if (!$parameters['ServiceName']) {
            $parameters['ServiceName'] = 'demoApp';
        }
        return $parameters;
    }

    protected function prepareParameters()
    {
        if (isset($_REQUEST['SAMLArt'])) {
            $this->getBindingsModule()->handleArtifact();
        }
        else {
            $this->convertAndVerifyMessages();
        }

        if (isset($_REQUEST['hSAMLRequest'])) {
            if (isset($_REQUEST['hSAMLResponse']['saml:EncryptedAssertion']) &&
                    $encryptedAssertion = $_REQUEST['hSAMLResponse']['saml:EncryptedAssertion']) {

                if (!isset($this->_entities['current']['keys']['private'])) {
                    throw new Corto_ProxyServer_Exception("Encrypted assertion found, but private key for {$this->_entities['current']['EntityId']} is not registered, " .
                            "unable to decrypt it to enrich assertion.");
                }

                $_REQUEST['hSAMLResponse']['saml:Assertion'] = $this->decryptElement(
                    $this->_entities['current']['keys']['private'],
                    $encryptedAssertion
                );
            }
        }

        if (isset($_REQUEST['hSAMLResponse'])) {
            $this->getBindingsModule()->prepareForSLO($_REQUEST['hSAMLResponse'], 'received');
        }

        $this->checkDestinationAudienceAndTiming();
    }

    function handleArtifact()
    {
        $artifacts = unpack('ntypecode/nendpointindex/H40sourceid/H40messagehandle', base64_decode($_REQUEST['SAMLArt']));
        $artifactResolve = array(
            'samlp:ArtifactResolve' => array(
                '_xmlns:samlp'  => 'urn:oasis:names:tc:SAML:2.0:protocol',
                '_xmlns:saml'   => 'urn:oasis:names:tc:SAML:2.0:assertion',
                '_ID'           => ID(),
                '_Version'      => '2.0',
                '_IssueInstant' => timeStamp(),
                'saml:Artifact' => array('__v' => $_REQUEST['SAMLArt']),
                'saml:Issuer'   => array('__v' => $GLOBALS['meta']['EntityID']),
            ),
        );

        $artifactResponse = soapRequest($GLOBALS['artifactResolutionServices'][$artifacts['sourceid']], $artifactResolve);
        if ($_REQUEST['hSAMLResponse'] = $artifactResponse['samlp:ArtifactResponse']['samlp:Response']) {
            $_REQUEST['hSAMLResponse']['__t'] = 'samlp:Response';
        }
        if ($_REQUEST['hSAMLRequest'] = $artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest']) {
            $_REQUEST['hSAMLRequest']['__t'] = 'samlp:AuthnRequest';
        }
    }

    protected function convertAndVerifyMessages()
    {
        if (isset($_GET['Signature'])) {
            $rawRequest = array();
            foreach (explode("&", $_SERVER['QUERY_STRING']) as $parameter) {
                if (preg_match("/^(.+)=(.*)$/", $parameter, $keyAndValue)) {
                    $rawRequest[$keyAndValue[1]] = $keyAndValue[2];
                }
            }
        }

        foreach (array('SAMLRequest', 'SAMLResponse') as $req) {
            $message = "";
            $messageHashKey = 'h' . $req;
            if (isset($_POST[$req])) {
                // HTTP-POST XML binding
                $message = base64_decode($_POST[$req]);
            }
            if (isset($_GET[$req])) {
                // HTTP-Redirect XML binding
                $message = gzinflate(base64_decode($_GET[$req]));
            }
            if ($message) {
                $_REQUEST[$messageHashKey] = Corto_XmlToArray::xml2array($message);
            }
            if (isset($_GET['j' . $req])) {
                // HTTP-Redirect JSON binding
                $_REQUEST[$messageHashKey] = json_decode(gzinflate(base64_decode($_GET['j' . $req])), 1);
            }
            if (!isset($_REQUEST[$messageHashKey])) {
                continue;
            }
            if (isset($_REQUEST['RelayState'])) {
                $_REQUEST[$messageHashKey]['__']['RelayState'] = $_REQUEST['RelayState'];
            }

            $remoteMeta = array();
            if (isset($GLOBALS['metabase']['remote'][$_REQUEST[$messageHashKey]['saml:Issuer']['__v']])) {
                $remoteMeta = $GLOBALS['metabase']['remote'][$_REQUEST[$messageHashKey]['saml:Issuer']['__v']];
            }

            $verify = ($req == 'SAMLRequest' && ((isset($remoteMeta['AuthnRequestsSigned']) && $remoteMeta['AuthnRequestsSigned']) || isset($GLOBALS['meta']['WantAuthnRequestsSigned']) && $GLOBALS['meta']['WantAuthnRequestsSigned']))
                    ||
                    ($req == 'SAMLResponse' && isset($GLOBALS['meta']['WantAssertionsSigned']) && $GLOBALS['meta']['WantAssertionsSigned']);
            if ($verify) {
                if (isset($remoteMeta['sharedkey']) && $sharedKey = $remoteMeta['sharedkey']) {
                    if (isset($_GET['Signature']) && $_GET['Signature']) {
                        $message = "j$req=" . $rawRequest['j' . $req] . (($relayState = $rawRequest['RelayState']) ? '&RelayState=' . $relayState : '');
                    }
                    else {
                        $message = $_POST['j' . $req];
                    }
                    if (base64_encode(sha1($sharedKey . sha1($message))) != $_REQUEST['Signature']) {
                        throw new Corto_ProxyServer_Exception('Integrity check failed (Sharedkey)');
                    }
                } elseif (isset($_GET['Signature']) && $signature = $_GET['Signature']) {
                    $message = "$req=" . $rawRequest[$req];
                    $message .= (($relayState = $rawRequest['RelayState']) ? '&RelayState=' . $relayState : '');
                    $message .= '&SigAlg=' . $rawRequest['SigAlg'];
                    $verified = openssl_verify($message, base64_decode($signature), $GLOBALS['certificates'][$_REQUEST[$messageHashKey]['saml:Issuer']['__v']]['public']);
                    if ($verified != 1) {
                        throw new Corto_ProxyServer_Exception('Integrity check failed (PKI)');
                    }
                } else {
                    if (!isset($GLOBALS['certificates'][$GLOBALS['meta']['EntityID']]['public'])) {
                        throw new Corto_ProxyServer_Exception("No public key found for {$GLOBALS['meta']['EntityID']}");
                    }

                    $verified = ($this->getSigningModule()->verify(
                        $GLOBALS['certificates'][$GLOBALS['meta']['EntityID']]['public'],
                        $message,
                        $_REQUEST[$messageHashKey]
                    ) || $this->getSigningModule()->verify(
                        $GLOBALS['certificates'][$GLOBALS['meta']['EntityID']]['public'],
                        $message,
                        $_REQUEST[$messageHashKey]['saml:Assertion']
                    ));
                    if (!$verified) {
                        throw new Corto_ProxyServer_Exception("Could not validate " . print_r($_REQUEST[$messageHashKey], 1));
                    }
                }
            }
            if ($req == 'SAMLRequest') {
                $forceAuthentication = &$_REQUEST[$messageHashKey]['_ForceAuthn'];
                $forceAuthentication = $forceAuthentication == 'true' || $forceAuthentication == '1';
                $isPassive = &$_REQUEST[$messageHashKey]['_IsPassive'];
                $isPassive = $isPassive == 'true' || $isPassive == '1';
            }
        }
    }


    ////////  ENCRYPTION /////////

    public function encryptElement($publicKey, $element, $tag = null)
    {
        if ($tag) {
            $element['__t'] = $tag;
        }
        $data = Corto_XmlToArray::array2xml($element);

        $cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        $iv         = mcrypt_create_iv(mcrypt_enc_get_iv_size($cipher), MCRYPT_DEV_URANDOM);
        $sessionKey = mcrypt_create_iv(mcrypt_enc_get_key_size($cipher), MCRYPT_DEV_URANDOM);

        mcrypt_generic_init($cipher, $sessionKey, $iv);
        $encryptedData = $iv . mcrypt_generic($cipher, $data);
        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);

        $publicKey = openssl_pkey_get_public($publicKey);
        $encryptedKey = "";
        openssl_public_encrypt($sessionKey, $encryptedKey, $publicKey, OPENSSL_PKCS1_PADDING);
        openssl_free_key($publicKey);

        $encryptedElement = array(
            'xenc:EncryptedData' => array(
                '_xmlns:xenc' => 'http://www.w3.org/2001/04/xmlenc#',
                '_Type' => 'http://www.w3.org/2001/04/xmlenc#Element',
                'ds:KeyInfo' => array(
                    '_xmlns:ds' => "http://www.w3.org/2000/09/xmldsig#",
                    'xenc:EncryptedKey' => array(
                        '_Id' => $this->getNewId(),
                        'xenc:EncryptionMethod' => array(
                            '_Algorithm' => "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
                        ),
                        'xenc:CipherData' => array(
                            'xenc:CipherValue' => array(
                                '__v' => base64_encode($encryptedKey),
                            ),
                        ),
                    ),
                ),
                'xenc:EncryptionMethod' => array(
                    '_Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                ),
                'xenc:CipherData' => array(
                    'xenc:CipherValue' => array(
                        '__v' => base64_encode($encryptedData),
                    ),
                ),
            ),
        );
        return $encryptedElement;
    }
    
    public function decryptElement($privateKey, $element, $asXML = false)
    {
        $encryptedKey  = base64_decode($element['xenc:EncryptedData']['ds:KeyInfo']['xenc:EncryptedKey']['xenc:CipherData']['xenc:CipherValue']['__v']);
        $encryptedData = base64_decode($element['xenc:EncryptedData']['xenc:CipherData']['xenc:CipherValue']['__v']);

        $privateKey = openssl_pkey_get_private($privateKey);
        openssl_private_decrypt($encryptedKey, $sessionKey, $privateKey, OPENSSL_PKCS1_PADDING);
        openssl_free_key($privateKey);

        $cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        $ivSize = mcrypt_enc_get_iv_size($cipher);
        $iv = substr($encryptedData, 0, $ivSize);

        mcrypt_generic_init($cipher, $sessionKey, $iv);

        $decryptedData = mdecrypt_generic($cipher, substr($encryptedData, $ivSize));
        mcrypt_generic_deinit($cipher);
        mcrypt_module_close($cipher);
        return $asXML ? $decryptedData : Corto_XmlToArray::xml2array($decryptedData);
    }

    ////////  ATTRIBUTE FILTERING /////////

    protected function filterInputAssertionAttributes(&$response)
    {
        $hostedEntityMetaData = $this->getCurrentEntity();

        $responseIssuer = $response['saml:Issuer']['__v'];
        $remoteEntityMetaData = $this->getRemoteEntity($responseIssuer);

        if (isset($remoteEntityMetaData['filter'])) {
            $this->callAttributeFilter($remoteEntityMetaData, $remoteEntityMetaData['filter'], $response);
        }
        if (isset($hostedEntityMetaData['infilter'])) {
            $this->callAttributeFilter($hostedEntityMetaData, $hostedEntityMetaData['infilter'], $response);
        }
    }

    protected function filterOutputAssertionAttributes(&$response)
    {
        $responseDestination = $response['__']['destinationid'];

        $hostedMetaData = $this->_entities['current'];
        $remoteMetaData = $this->_entities['remote'][$responseDestination];

        if (isset($remoteMetaData['filter'])) {
            $this->callAttributeFilter($remoteMetaData, $remoteMetaData['filter'], $response);
        }
        if ($hostedMetaData['outfilter']) {
            $this->callAttributeFilter($hostedMetaData, $hostedMetaData['outfilter'], $response);
        }
    }

    protected function callAttributeFilter($entityMetaData, $callback, $response)
    {
        if (!$callback || !is_callable($callback)) {
            // @todo Non existing callbacks shouldn't give an exception, just a warning...
            throw new Corto_ProxyServer_Exception('callback: ' . var_export($callback, true) . ' isn\'t callable');
        }

        $responseAssertionAttributes = &$response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute'];

        // Take the attributes out
        $attributes = Corto_XmlToArray::attributes2array($responseAssertionAttributes);

        // Pass em along
        $callback($entityMetaData, $response, $attributes);

        // Put em back
        $responseAssertionAttributes = Corto_XmlToArray::array2attributes($attributes);
    }

    ////////  TEMPLATE RENDERING /////////

    public function renderTemplate($templateName, $vars = array(), $parentTemplates = array())
    {
        if (is_array($vars)) {
            extract($vars);
        }
        else {
            $content = $vars;
        }

        $templateFileName = $templateName . '.tpl.php';

        ob_start();

        $this->_renderTemplate($templateFileName);

        $content = ob_get_contents();
        ob_end_clean();

        foreach ($parentTemplates as $parentTemplate) {
            $content = $this->renderTemplate(
                $parentTemplate,
                array(
                    'content' => $content,
                )
            );
        }
        return $content;
    }

    protected function _renderTemplate($templateFileName)
    {
        $source = $this->getTemplateSource();
        switch ($source['type'])
        {
            case self::TEMPLATE_SOURCE_MEMORY:
                if (!isset($source['arguments'][$templateFileName])) {
                    throw new Corto_ProxyServer_Exception("Unable to load template '$templateFileName' from memory!");
                }

                eval('?>' . $source['arguments'][$templateFileName] . '<?');
                break;

            case self::TEMPLATE_SOURCE_FILESYSTEM;
                if (!isset($source['arguments']['filepath'])) {
                    throw new Corto_ProxyServer_Exception('Template path not set, unable to render templates from filesystem!');
                }

                $filePath = $source['arguments']['filepath'] . $templateFileName;
                if (!file_exists($filePath)) {
                    throw new Corto_ProxyServer_Exception('Template file does not exist: ' . $filePath);
                }

                include($filePath);
                break;
        }
    }

    //////// OUTPUT /////////

    protected function redirect($location, $message = null)
    {
        if (!$this->getConfig('debug', false)) {
            $this->sendHeader('Location', $location);
        }

        $this->renderTemplate('redirect', array('location'=>$location));
    }

    public function sendHeader($name, $value)
    {
        return header("$name: $value");
    }

    public function sendOutput($rawOutput)
    {
        return print $rawOutput; 
    }

    //////// UTILITIES /////////

    /**
     * Generate a SAML datetime with a given delta in seconds.
     *
     * Delta 0 gives current date and time, delta 3600 is +1 hour, delta -3600 is -1 hour.
     *
     * @param int $deltaSeconds
     * @return string
     */
    protected function timeStamp($deltaSeconds = 0)
    {
        return gmdate('Y-m-d\TH:i:s\Z', time() + $deltaSeconds);
    }

    public function getNewId()
    {
        return sha1(uniqid(mt_rand(), true));
    }

    protected function startSession()
    {
        session_set_cookie_params(0, $this->getConfig('cookie_path'), '', $this->getConfig('use_secure_cookies', true));
        session_name($this->_entities['current']['EntityCode']);
        session_start();
    }

    protected function restartSession($newId, $newName)
    {
        session_write_close();

        session_id($newId);
        session_name($newName);
        session_start();
    }


    public function getLogger()
    {

    }

    public function setLogger()
    {
        
    }
}
