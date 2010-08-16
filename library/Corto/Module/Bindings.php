<?php

class Corto_Module_Bindings_Exception extends Corto_ProxyServer_Exception
{
}

class Corto_Module_Bindings_VerificationException extends Corto_Module_Bindings_Exception
{
}

class Corto_Module_Bindings extends Corto_Module_Abstract
{
    const ARTIFACT_BINARY_FORMAT = 'ntypecode/nendpointindex/H40sourceid/H40messagehandle';

    const KEY_ARTIFACT = 'SAMLArt';
    const KEY_REQUEST  = 'SAMLRequest';
    const KEY_RESPONSE = 'SAMLResponse';

    protected $_bindings = array(
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'        => '_sendHTTPRedirect',
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'            => '_sendHTTPPost',
            //'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'        => 'sendHTTPArtifact',
            //'urn:oasis:names:tc:SAML:2.0:bindings:URI'                  => 'sendURI',
            //'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'                 => 'sendSOAP',
            //'INTERNAL'                                                  => 'sendInternal',
            'JSON-Redirect'                                             => '_sendHTTPRedirect',
            'JSON-POST'                                                 => '_sendHTTPPost',
            null                                                        => '_sendHTTPRedirect',

            //'urn:oasis:names:tc:SAML:1.0:profiles:browser-post'         => 'sendbrowserpost',
            //'urn:oasis:names:tc:SAML:1.0:profiles:browser-artifact-01'  => 'sendbrowserartifact01',
            //'urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding'         => 'xxxx',
            //'urn:mace:shibboleth:1.0:profiles:AuthnRequest'             => 'sendShibAuthnRequest',
    );

    public function receiveRequest()
    {
        $request = $this->_receiveMessage(self::KEY_REQUEST);
        $this->_server->getSessionLog()->debug("Received request: " . var_export($request['Message'], true));

        $this->_verifyRequest($request);
        $this->_c14nRequest($request);

        return $request['Message'];
    }

    public function receiveResponse()
    {
        $response = $this->_receiveMessage(self::KEY_RESPONSE);
        $this->_server->getSessionLog()->debug("Received response: " . var_export($response['Message'], true));

        $this->_decryptResponse($response);
        $this->_verifyResponse($response);
        
        return $response['Message'];
    }

    protected function _receiveMessage($key)
    {
        $message = $this->_receiveMessageFromArtifact($key);
        if (!empty($message)) {
            return $message;
        }

        $message = $this->_receiveMessageFromHttpPost($key);
        if (!empty($message)) {
            return $message;
        }

        $message = $this->_receiveMessageFromHttpRedirect($key);
        if (!empty($message)) {
            return $message;
        }

        throw new Corto_Module_Bindings_Exception("Unable to receive message '$key'");
    }

    protected function _receiveMessageFromArtifact($key)
    {
        if (!isset($_REQUEST[self::KEY_ARTIFACT])) {
            return false;
        }

        $artifacts = base64_decode($_REQUEST[self::KEY_ARTIFACT]);
        $artifacts = unpack(self::ARTIFACT_BINARY_FORMAT, $artifacts);

        $artifactResolveMessage = array(
            'samlp:ArtifactResolve' => array(
                '_xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
                '_xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
                '_ID'           => $this->_server->getNewId(),
                '_Version'      => '2.0',
                '_IssueInstant' => $this->_server->timeStamp(),

                'saml:Artifact' => array('__v' => $_REQUEST['SAMLArt']),
                'saml:Issuer'   => array('__v' => $this->_server->getCurrentEntityUrl()),
            ),
        );

        if (!isset($artifacts['sourceid'])) {
            throw new Corto_Module_Bindings_Exception("No Source ID found in SAML2 Artifact?!");
        }

        $sourceEntity = $this->_server->getRemoteEntity($artifacts['sourceid']);
        if (!$sourceEntity) {
            throw new Corto_Module_Bindings_Exception("Entity {$artifacts['sourceid']} mentioned in SAML2 Artifact not registered!");
        }
        if (!isset($sourceEntity['ArtifactResolutionServiceLocation'])) {
            throw new Corto_Module_Bindings_Exception("Entity {$artifacts['sourceid']} mentioned in SAML2 Artifact found, but no Artifact Resolution Service is registered");
        }

        $artifactResponse = $this->_soapRequest($sourceEntity['ArtifactResolutionServiceLocation'], $artifactResolveMessage);

        if ($key === self::KEY_REQUEST) {
            if (isset($artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest'])) {
                $message = $artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest'];
                $message[Corto_XmlToArray::TAG_NAME_KEY] = 'samlp:AuthnRequest';
            }
            else {
                return false;
            }
        }
        else if ($key === self::KEY_RESPONSE) {
            if (isset($artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest'])) {
                $message = $artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest'];
                $message[Corto_XmlToArray::TAG_NAME_KEY] = 'samlp:Response';
            }
            else {
                return false;
            }
        }

        $relayState = $_REQUEST['RelayState'];
        $message[Corto_XmlToArray::PRIVATE_KEY_PREFIX]['RelayState'] = $relayState;

        return array(
            'Message'    => $message,
            'RelayState' => $relayState,
        );
    }

    protected function _receiveMessageFromHttpPost($key)
    {
        if (!isset($_POST[$key])) {
            return false;
        }

        $message        = base64_decode($_POST[$key]);
        $messageArray   = $this->_getArrayFromReceivedMessage($message);
        
        $relayState     = $_POST['RelayState'];
        $messageArray[Corto_XmlToArray::PRIVATE_KEY_PREFIX]['RelayState'] = $relayState;
        
        return array(
            'Message'    => $messageArray,
            'MessageRaw' => $message,
            'RelayState' => $relayState
        );
    }

    protected function _receiveMessageFromHttpRedirect($key)
    {
        if (!isset($_GET[$key])) {
            return false;
        }

        $message = gzinflate(base64_decode($_GET[$key]));
        $messageArray       = $this->_getArrayFromReceivedMessage($message);

        $relayState = "";
        if (isset($_GET['RelayState'])) {
            $relayState         = $_GET['RelayState'];
            $messageArray[Corto_XmlToArray::PRIVATE_KEY_PREFIX]['RelayState'] = $relayState;
        }

        $signature = "";
        $signingAlgorithm = "";
        if (isset($_GET['Signature'])) {
            $signature          = $_GET['Signature'];
            $signingAlgorithm   = $_GET['SigAlg'];
        }

        return array(
            'Message'           => $messageArray,
            'MessageRaw'        => $message,
            'RelayState'        => $relayState,
            'Signature'         => $signature,
            'SigningAlgorithm'  => $signingAlgorithm,
        );
    }

    protected function _getArrayFromReceivedMessage($message)
    {
        $messageDecoded = json_decode($message);
        if ($messageDecoded) {
            return $messageDecoded;
        }

        return Corto_XmlToArray::xml2array($message);
    }

    protected function _verifyRequest(array $request)
    {
        $requestIssuer = $request['Message']['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($requestIssuer);
        if ($remoteEntity===null) {
            throw new Corto_Module_Bindings_Exception("Request Issuer '{$requestIssuer}' is not a known remote entity? (please add SP to Remote Entities)");
        }

        if ((isset($remoteEntity['AuthnRequestsSigned']) && $remoteEntity['AuthnRequestsSigned']) ||
            ($this->_server->getCurrentEntitySetting('WantsAuthnRequestsSigned', false))) {
            $this->_verifySignatureMessage($request, self::KEY_REQUEST);
        }
        
        $this->_verifyMessageDestinedForUs($request['Message']);
    }

    protected function _c14nRequest(array $request)
    {
        $forceAuthentication = &$request['_ForceAuthn'];
        $forceAuthentication = $forceAuthentication == 'true' || $forceAuthentication == '1';

        $isPassive = &$request['_IsPassive'];
        $isPassive = $isPassive == 'true' || $isPassive == '1';
    }

    protected function _decryptResponse(array $response)
    {
        if (isset($response['saml:EncryptedAssertion'])) {
            $encryptedAssertion = $response['saml:EncryptedAssertion'];

            $currentCertificates = $this->_server->getCurrentEntitySetting('certificates', array());
            if (!isset($currentCertificates['private'])) {
                $exceptionMessage = "Encrypted assertion found, but private key for ".
                        $this->_server->getCurrentEntityUrl().
                        " is not registered, unable to decrypt it to enrich assertion.";
                throw new Corto_Module_Bindings_Exception($exceptionMessage);
            }

            $response['saml:Assertion'] = $this->_decryptElement(
                $currentCertificates['private'],
                $encryptedAssertion
            );
        }
    }

    protected function _decryptElement($privateKey, $element, $returnAsXML = false)
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

        if ($returnAsXML) {
            return $decryptedData;
        }
        return Corto_XmlToArray::xml2array($decryptedData);
    }

    protected function _verifyResponse(array $response)
    {
        if ($this->_server->getCurrentEntitySetting('WantsAssertionsSigned', true)) {
            $this->_verifySignatureMessage($response, self::KEY_RESPONSE);
        }
        $this->_verifyMessageDestinedForUs($response['Message']);
        $this->_verifyTimings($response);
    }

    protected function _verifySignature(array $message, $key)
    {
        if (isset($message['Signature'])) { // We got a Signature in the URL (HTTP Redirect)
            return $this->_verifySignatureMessage($message, $key);
        }

        // Otherwise it's in the message or in the assertion in the message (HTTP Post Response)
        $messageIssuer = $message['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($messageIssuer);

        $messageVerified = $this->_verifySignatureXMLElement(
            $remoteEntity['certificates']['public'],
            $message['MessageRaw'],
            $message['Message']
        );

        if (!isset($message['Message']['saml:Assertion'])) {
            return $messageVerified;
        }

        $assertionVerified = $this->_verifySignatureXMLElement(
            $remoteEntity['certificates']['public'],
            $message['MessageRaw'],
            $message['Message']['saml:Assertion']
        );
        return ($messageVerified || $assertionVerified);
    }

    protected function _verifySignatureMessage($message, $key)
    {
        $rawGet = $this->_server->getRawGet();

        $queryString = "$key=" . $rawGet[$key];
        if (isset($rawGet[$key])) {
            $queryString .= '&RelayState=' . $rawGet['RelayState'];
        }
        $queryString .= '&SigAlg=' . $rawGet['SigAlg'];

        $messageIssuer = $message['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($messageIssuer);

        $verified = openssl_verify(
            $queryString,
            base64_decode($message['Signature']),
            $remoteEntity['certificates']['public']);

        return ($verified === 1);
    }
    

    protected function _verifySignatureXMLElement($publicKey, $xml, $element)
    {
        $signatureValue = base64_decode($element['ds:Signature']['ds:SignatureValue']['__v']);
        $digestValue = base64_decode($element['ds:Signature']['ds:SignedInfo']['ds:Reference']['ds:DigestValue']['__v']);
        $id = $element['_ID'];

        $document = DOMDocument::loadXML($xml);
        $xp = new DomXPath($document);
        $xp->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $signedElement = $xp->query("//*[@ID = '$id']")->item(0);
        $signature = $xp->query(".//ds:Signature", $signedElement)->item(0);
        $signedInfo = $xp->query(".//ds:SignedInfo", $signature)->item(0)->C14N(true, false);
        $signature->parentNode->removeChild($signature);
        $canonicalXml = $signedElement->C14N(true, false);

        return sha1($canonicalXml, TRUE) == $digestValue && openssl_verify($signedInfo, $signatureValue, $publicKey) == 1;
    }

    protected function _verifyMessageDestinedForUs(array $message)
    {
        $destinationId = $message['_Destination'];
        if ($destinationId) { // Destination is optional
            if (strpos($this->_server->getCurrentEntityUrl(), $destinationId) !== 0) {
                //throw new Corto_Module_Bindings_VerificationException("Destination: '$destinationId' is not here");
            }
        }
        return true;
    }

    protected function _verifyTimings(array $message)
    {
        // just use string cmp all times in ISO like format without timezone (but everybody appends a Z anyways ...)
        $skew = $this->_server->getConfig('max_age_seconds', 3600);
        $aShortWhileAgo = $this->_server->timeStamp(-$skew);
        $inAShortWhile  = $this->_server->timeStamp($skew);
        $issues = array();

        // Check SAMLResponse SubjectConfirmation timings

        if (isset($message['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_NotBefore'])) {
            if ($inAShortWhile < $message['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_NotBefore']) {
                $issues[] = 'SubjectConfirmation not valid yet';
            }
        }

        if (isset($message['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_NotOnOrAfter'])) {
            if ($aShortWhileAgo > $message['saml:Assertion']['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_NotOnOrAfter']) {
                $issues[] = 'SubjectConfirmation too old';
            }
        }

        // Check SAMLResponse Conditions timings

        if (isset($message['saml:Assertion']['saml:Conditions']['_NotBefore'])) {
            if ($inAShortWhile < $message['saml:Assertion']['saml:Conditions']['_NotBefore']) {
                $issues[] = 'Assertion Conditions not valid yet';
            }
        }

        if (isset($message['saml:Assertion']['saml:Conditions']['_NotOnOrAfter'])) {
            if ($aShortWhileAgo > $message['saml:Assertion']['saml:Conditions']['_NotOnOrAfter']) {
                $issues[] = 'Assertions Condition too old';
            }
        }

        // Check SAMLResponse AuthnStatement timing

        if (isset($message['saml:Assertion']['saml:AuthnStatement']['_SessionNotOnOrAfter'])) {
            if ($aShortWhileAgo > $message['saml:Assertion']['saml:AuthnStatement']['_SessionNotOnOrAfter']) {
                $issues[] = 'AuthnStatement Session too old';
            }
        }

        if (!empty($issues)) {
            $message = 'Problems detected with timings! Please check if your server has the correct time set.';
            $message .= ' Issues: '.implode(PHP_EOL, $issues);
            throw new Corto_Module_Bindings_Exception($message);
        }
        return true;
    }

    protected function _soapRequest($soapServiceUrl, array $body)
    {
        $soapEnvelope = array(
            '__t' => 'SOAP-ENV:Envelope',
            '_xmlns:SOAP-ENV' => "http://schemas.xmlsoap.org/soap/envelope/",
            'SOAP-ENV:Body' => $body,
        );

        $curlOptions = array(
            CURLOPT_URL             => $soapServiceUrl,
            CURLOPT_HTTPHEADER      => array('SOAPAction: ""'),
            CURLOPT_RETURNTRANSFER  => 1,
            CURLOPT_SSL_VERIFYPEER  => FALSE,
            CURLOPT_POSTFIELDS      => Corto_XmlToArray::array2xml($soapEnvelope),
            CURLOPT_HEADER          => 0,
        );

        $curlHandler = curl_init();
        curl_setopt_array($curlHandler, $curlOptions);
        $curlResult = curl_exec($curlHandler);

        $soapResponse = Corto_XmlToArray::xml2array($curlResult);

        return $soapResponse['SOAP-ENV:Body'];
    }

    protected function _soapResponse(array $body)
    {
        $soapResponse = array(
            '__t'               => 'SOAP-ENV:Envelope',
            'xmlns:SOAP-ENV'    => "http://schemas.xmlsoap.org/soap/envelope/",
            'SOAP-ENV:Body'     => $body,
        );
        $xml = Corto_XmlToArray::array2xml($soapResponse);

        $this->_server->sendHeader('Content-Type', 'application/xml');
        $this->_server->sendOutput($xml);
    }

    public function send($message, $remoteEntity)
    {
        $bindingUrn = $message['__']['ProtocolBinding'];
        $function = $this->_bindings[$bindingUrn];
        
        $this->$function($message, $remoteEntity);
    }

    protected function _sendHTTPRedirect($message, $remoteEntity)
    {
        $messageType = $message['__']['paramname'];

        // Determine if we should sign the message
        $wantRequestsSigned = ($remoteEntity['WantsAuthnRequestsSigned'] ||
                                $this->_server->getCurrentEntitySetting('AuthnRequestsSigned'));
        $mustSign = ($messageType===self::KEY_REQUEST && !$wantRequestsSigned);
        if ($mustSign) {
            unset($message['ds:Signature']);
        }

        // Encode the message in destination format
        if (isset($remoteEntity['WantsJson'])) {
            $encodedMessage = json_encode($message);
        }
        else {
            $encodedMessage = Corto_XmlToArray::array2xml($message);
        }

        // Encode the message for transfer
        $encodedMessage = urlencode(base64_encode(gzdeflate($encodedMessage)));

        // Build the query string
        if ($message['__']['ProtocolBinding'] == 'JSON-Redirect') {
            $queryString = "j$messageType = $encodedMessage";
        }
        else {
            $queryString = "$messageType=" . $encodedMessage;
        }
        $queryString .= $message['__']['RelayState'] ? '&RelayState=' . urlencode($message['__']['RelayState']) : "";
        $queryString .= $message['__']['target']     ? '&target='     . urlencode($message['__']['target'])     : "";

        // Sign the message
        if (isset($remoteEntity['SharedKey'])) {
            $queryString .= "&Signature=" . urlencode(base64_encode(sha1($remoteEntity['SharedKey'] . sha1($queryString))));
        } elseif ($mustSign) {
            $queryString .= '&SigAlg=' . urlencode($this->_server->getConfig('SigningAlgorithm'));

            $key = openssl_pkey_get_private($GLOBALS['certificates'][$GLOBALS['meta']['EntityID']]['private']);
            $signature = "";
            openssl_sign($queryString, $signature, $key);
            openssl_free_key($key);

            $queryString .= '&Signature=' . urlencode(base64_encode($signature));
        }

        // Build the full URL
        $location = $message['_Destination'] . $message['_Recipient']; # shib remember ...
        $location .= "?" . $queryString;

        // Redirect
        $this->_server->redirect($location, $message);
    }

    protected function _sendHTTPPost($message, $remoteEntity)
    {
        $name = $message['__']['paramname'];
        if ($message['__']['ProtocolBinding'] == 'JSON-POST') {
            if ($relayState = $message['__']['RelayState']) {
                $relayState = "&RelayState=$relayState";
            }
            $name = 'j' . $name;
            $encodedMessage = json_encode($message);
            $signatureHTMLValue = htmlspecialchars(base64_encode(sha1($remoteEntity['sharedkey'] . sha1("$name=$message$relayState"))));
            $extra .= '<input type="hidden" name="Signature" value="' . $signatureHTMLValue . '">';

        } else {
            if ($name == 'SAMLRequest' && ($remoteEntity['WantsAuthnRequestsSigned'] || $GLOBALS['meta']['AuthnRequestsSigned'])) {
                $message = $this->_sign(
                    $GLOBALS['certificates'][$GLOBALS['meta']['entitycode']]['private'],
                    $message
                );
            }
            else if ($name == 'SAMLResponse' && isset($remoteEntity['WantsAssertionsSigned']) && $remoteEntity['WantsAssertionsSigned']) {
                $message['saml:Assertion']['__t'] = 'saml:Assertion';
                $message['saml:Assertion']['_xmlns:saml'] = "urn:oasis:names:tc:SAML:2.0:assertion";
                unset($message['saml:Assertion']['ds:Signature']);
                ksort($message['saml:Assertion']);

                $message['saml:Assertion'] = $this->_sign(
                    $GLOBALS['certificates'][$GLOBALS['meta']['EntityID']]['private'],
                    $message['saml:Assertion']
                );
                ksort($message['saml:Assertion']);
                #$enc = docrypt(certs::$server_crt, $message['saml:Assertion'], 'saml:EncryptedAssertion');

            }
            else if ($name == 'SAMLResponse' && isset($remoteEntity['WantsResponsesSigned']) && $remoteEntity['WantsResponsesSigned']) {
                $message = $this->_sign(
                    $GLOBALS['certificates'][$GLOBALS['meta']['EntityID']]['private'],
                    $message
                );
            }
            $encodedMessage = Corto_XmlToArray::array2xml($message);
        }

        $extra = $message['__']['RelayState'] ? '<input type="hidden" name="RelayState" value="' . htmlspecialchars($message['__']['RelayState']) . '">' : '';
        $extra .= $message['__']['target']    ? '<input type="hidden" name="target" value="'     . htmlspecialchars($message['__']['target']) . '">' : '';
        $encodedMessage = htmlspecialchars(base64_encode($encodedMessage));

        $action = $message['_Destination'] . (isset($message['_Recipient'])?$message['_Recipient']:'');
        $output = $this->_server->renderTemplate(
            'form',
            array(
                'action' => $action,
                'message' => $encodedMessage,
                'xtra' => $extra,
                'name' => $name,
                'trace' => '',//$this->_server->debugRequest($action, $message),
        ));
        $this->_server->sendOutput($output);
    }
    
    protected function _sign($privateKey, $element)
    {
        $signature = array(
            '__t' => 'ds:Signature',
            '_xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
            'ds:SignedInfo' => array(
                '__t' => 'ds:SignedInfo',
                '_xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
                'ds:CanonicalizationMethod' => array(
                    '_Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
                ),
                'ds:SignatureMethod' => array(
                    '_Algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                ),
                'ds:Reference' => array(
                    '_URI' => '__placeholder__',
                    'ds:Transforms' => array(
                        'ds:Transform' => array(
                            '_Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
                        ),
                    ),
                    'ds:DigestMethod' => array(
                        '_Algorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1',
                    ),
                    'ds:DigestValue' => array(
                        '__v' => '__placeholder__',
                    ),
                ),
            ),
        );

        $key = openssl_pkey_get_private($privateKey);
        $canonicalXml = DOMDocument::loadXML(Corto_XmlToArray::array2xml($element))->firstChild->C14N(true, false);

        $signature['ds:SignedInfo']['ds:Reference']['ds:DigestValue']['__v'] = base64_encode(sha1($canonicalXml, TRUE));
        $signature['ds:SignedInfo']['ds:Reference']['_URI'] = "#" . $element['_ID'];

        $canonicalXml2 = DOMDocument::loadXML(Corto_XmlToArray::array2xml($signature['ds:SignedInfo']))->firstChild->C14N(true, false);

        openssl_sign($canonicalXml2, $signatureValue, $key);

        openssl_free_key($key);
        $signature['ds:SignatureValue']['__v'] = base64_encode($signatureValue);
        foreach ($element as $tag => $item) {
            if ($tag == 'ds:Signature') {
                continue;
            }

            $newElement[$tag] = $item;

            if ($tag == 'saml:Issuer') {
                $newElement['ds:Signature'] = $signature;
            }
        }

        return $newElement;
    }
}