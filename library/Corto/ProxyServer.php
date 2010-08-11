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
    const MODULE_SERVICES   = 'Services';

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

    public function getCurrentEntityUrl($serviceName = "", $remoteEntityId = "")
    {
        return $this->getHostedEntityUrl($serviceName, $this->_entities['current']['EntityCode'], $remoteEntityId);
    }

    public function getCurrentEntitySetting($name, $default = null)
    {
        if (isset($this->_entities['current'][$name])) {
            return $this->_entities['current'][$name];
        }
        return $default;
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

        $serviceName = $parameters['ServiceName'];
        $this->getServicesModule()->$serviceName();
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

        // Defaults
        if (!$parameters['EntityCode']) {
            $parameters['EntityCode'] = 'main';
        }
        if (!$parameters['ServiceName']) {
            $parameters['ServiceName'] = 'demoApp';
        }

        return $parameters;
    }

    //////// RESPONSE HANDLING ////////

    public function createErrorResponse($request, $errorStatus)
    {
        $response = $this->_createBaseResponse($request);

        $errorCodePrefix = 'urn:oasis:names:tc:SAML:2.0:status:';
        $response['samlp:Status'] = array(
            'samlp:StatusCode' => array(
                '_Value' => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
                'samlp:StatusCode' => array(
                    '_Value' => $errorCodePrefix . $errorStatus,
                ),
            ),
        );
        return $response;
    }

    public function createEnhancedResponse($request, $sourceResponse)
    {
        $response = $this->_createBaseResponse($request);

        $response['samlp:Status']   = $sourceResponse['samlp:Status'];
        $response['saml:Assertion'] = $sourceResponse['saml:Assertion'];

        // remove us from the list otherwise we will as a proxy be there multiple times
        // as the assertion passes through multiple times ???
        $authenticatingAuthorities = &$response['saml:Assertion']['saml:AuthnStatement']['saml:AuthnContext']['saml:AuthenticatingAuthority'];
        foreach ((array) $authenticatingAuthorities as $key => $authenticatingAuthority) {
            if ($authenticatingAuthority['__v'] == $GLOBALS['meta']['EntityID']) {
                unset($authenticatingAuthorities[$key]);
            }
        }

        if ($this->getCurrentEntityUrl() !== $sourceResponse['saml:Issuer']['__v']) {
            $authenticatingAuthorities[] = array('__v' => $sourceResponse['saml:Issuer']['__v']);
        }

        $subjectConfirmation = &$response['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData'];
        $subjectConfirmation['_Recipient']    = $request['_AssertionConsumerServiceURL'];
        $subjectConfirmation['_InResponseTo'] = $request['_ID'];

        $response['saml:Assertion']['saml:Conditions']['saml:AudienceRestriction']['saml:Audience']['__v'] = $request['saml:Issuer']['__v'];

        return $response;
    }

    public function createNewResponse($request, $attributes = array())
    {
        $response = $this->_createBaseResponse($request);

        $soon       = $this->timeStamp($this->getConfig('NotOnOrAfter', 300));
        $sessionEnd = $this->timeStamp($this->getConfig('SessionEnd', 60 * 60 * 12));

        $response['saml:Assertion'] = array(
            '_xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
            '_xmlns:xs' => 'http://www.w3.org/2001/XMLSchema',
            '_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
            '_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',

            '_ID'           => $this->getNewId(),
            '_Version'      => '2.0',
            '_IssueInstant' => $response['_IssueInstant'],

            'saml:Issuer' => array('__v' => $response['saml:Issuer']['__v']),
            'ds:Signature' => '__placeholder__',
            'saml:Subject' => array(
                'saml:NameID' => array(
                    '_SPNameQualifier'  => $GLOBALS['meta']['EntityID'],
                    '_Format'           => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    '__v'               => $this->getNewId(),
                ),
                'saml:SubjectConfirmation' => array(
                    '_Method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
                    'saml:SubjectConfirmationData' => array(
                        '_NotOnOrAfter' => $soon,
                        '_Recipient'    => $request['_AssertionConsumerServiceURL'], # req issuer
                        '_InResponseTo' => $request['_ID'],
                    ),
                ),
            ),
            'saml:Conditions' => array(
                '_NotBefore'    => $response['_IssueInstant'],
                '_NotOnOrAfter' => $soon,
                'saml:AudienceRestriction' => array(
                    'saml:Audience' => array('__v' => $request['saml:Issuer']['__v']),
                ),
            ),
            'saml:AuthnStatement' => array(
                '_AuthnInstant'         => $response['_IssueInstant'],
                '_SessionNotOnOrAfter'  => $sessionEnd,
                'saml:SubjectLocality' => array(
                    '_Address' => $_SERVER['REMOTE_ADDR'],
                    '_DNSName' => $_SERVER['REMOTE_HOST'],
                ),
                'saml:AuthnContext' => array(
                    'saml:AuthnContextClassRef' => array('__v' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'),
                ),
            ),
        );

        $attributes['binding'][] = $response['__']['ProtocolBinding'];
        foreach ((array) $attributes as $key => $vs) {
            foreach ($vs as $v) {
                $attributeStatement[$key][] = $v;
            }
        }

        $attributeConsumingServiceIndex = $request['_AttributeConsumingServiceIndex'];
        if ($attributeConsumingServiceIndex) {
            $attributeStatement['AttributeConsumingServiceIndex'] = "AttributeConsumingServiceIndex: $attributeConsumingServiceIndex";
        }
        else {
            $attributeStatement['AttributeConsumingServiceIndex'] = '-no AttributeConsumingServiceIndex given-';
        }

        $response['saml:Assertion']['saml:AttributeStatement']['saml:Attribute'] = Corto_XmlToArray::array2attributes($attributeStatement);
        $extraAttributes = Array(
            '_Name' => 'xuid',
            '_NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
            'saml:AttributeValue' => Array(
                Array(
                    '_xsi:type' => 'xs:string',
                    '__v' => 'abc@xxx',
                ),
                Array(
                    '_xsi:type' => 'xs:string',
                    '__v' => 'def@yyy',
                ),
            ),
        );

        $extraEncryptedAttributes = $this->getEncryptionModule()->encryptElement(
            $GLOBALS['certificates'][$this->_entities['current']['EntityID']]['public'],
            $extraAttributes,
            'saml:EncryptedAttribute'
        );
        $response['saml:Assertion']['saml:AttributeStatement']['saml:EncryptedAttribute'][] = $extraEncryptedAttributes;

        return $response;
    }

    protected function _createBaseResponse($request)
    {
        $now = $this->timeStamp();
        $response = array(
            Corto_XmlToArray::TAG_NAME_KEY => 'samlp:Response',
            Corto_XmlToArray::PRIVATE_KEY_PREFIX => array(
                'paramname' => 'SAMLResponse',
                'RelayState'=> $request['__']['RelayState'],
                'target'    => $request['__']['target'],
            ),
            '_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
            '_xmlns:saml'  => 'urn:oasis:names:tc:SAML:2.0:assertion',

            '_ID'           => $this->getNewId(),
            '_Version'      => '2.0',
            '_IssueInstant' => $now,
            '_InResponseTo' => $request['_ID'],

            'saml:Issuer' => array('__v' => $this->getCurrentEntityUrl()),
            'samlp:Status' => array(
                'samlp:StatusCode' => array(
                    '_Value' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
                ),
            ),
        );

        $destinationID = $request['saml:Issuer']['__v'];
        $response['__']['destinationid'] = $destinationID;

        if ($acsUrl = $request['_AssertionConsumerServiceURL']) {
            $response['_Destination'] = $acsUrl;
            $response['__']['ProtocolBinding'] = $request['_ProtocolBinding'];
        } else {
            $remoteEntity = $this->getRemoteEntity($destinationID);
            $remoteAcs = $remoteEntity['AssertionConsumerService'];

            $response['_Destination']           = $remoteAcs['Location'];
            $response['__']['ProtocolBinding']  = $remoteAcs['Binding'];
        }

        if (!$response['_Destination']) {
            throw new Corto_ProxyServer_Exception("No Destination in request or metadata for: $destinationID");
        }

        return $response;
    }

    function sendResponse($request, $response)
    {
        $requestIssuer = $request['saml:Issuer']['__v'];
        $sp = $this->getRemoteEntity($requestIssuer);

        if ($response['samlp:Status']['samlp:StatusCode']['_Value'] == 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            $this->filterOutputAssertionAttributes($response);

            return $this->send($response, $sp);
        }
        
        unset($response['saml:Assertion']);
        $this->send($response, $sp);
    }

    ////////  REQUEST HANDLING /////////

    public function sendAuthenticationRequest(array $request, $idp, $scope = null)
    {
        $id = $request['_ID'];
        $_SESSION[$id]['SAMLRequest'] = $request;

        $newRequest = $this->createRequest($idp, $scope);

        $newId = $newRequest['_ID'];
        $_SESSION[$newId]['_InResponseTo'] = $id;

        $this->getBindingsModule()->send($newRequest, $this->_entities['remote'][$idp]);
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

    /**
     * Parse the HTTP URL query string and return the (raw) parameters in an array.
     *
     * We need to do this ourselves, so that we get access to the raw (url encoded) values.
     * This is required because different software can url encode to different values.
     *
     * @return array Raw parameters form the query string
     */
    public function getRawGet()
    {
        $rawGet = array();
        foreach (explode("&", $_SERVER['QUERY_STRING']) as $parameter) {
            if (preg_match("/^(.+)=(.*)$/", $parameter, $keyAndValue)) {
                 $rawGet[$keyAndValue[1]] = $keyAndValue[2];
            }
        }
        return $rawGet;
    }

    public function redirect($location, $message = null)
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
