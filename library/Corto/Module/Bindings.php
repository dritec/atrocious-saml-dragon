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

    public function receiveRequest()
    {
        $request = $this->_receiveMessage(self::KEY_REQUEST);
        $this->_verifyRequest($request);
        $this->_c14nRequest($request);
        return $request['message'];
    }

    public function receiveResponse()
    {
        $response = $this->_receiveMessage(self::KEY_RESPONSE);
        $this->_decryptResponse($response);
        $this->_verifyResponse($response);
        return $response['message'];
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
        if (!isset($sourceEntity['artifactResolutionService'])) {
            throw new Corto_Module_Bindings_Exception("Entity {$artifacts['sourceid']} mentioned in SAML2 Artifact found, but no Artifact Resolution Service is registered");
        }

        $artifactResponse = $this->soapRequest($sourceEntity['artifactResolutionService'], $artifactResolveMessage);

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

        $relayState         = $_GET['RelayState'];
        $messageArray[Corto_XmlToArray::PRIVATE_KEY_PREFIX]['RelayState'] = $relayState;

        $signature          = $_GET['Signature'];
        $signingAlgorithm   = $_GET['SigAlg'];

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
        $requestIssuer = $request['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($requestIssuer);

        if ((isset($remoteEntity['AuthnRequestsSigned']) && $remoteEntity['AuthnRequestsSigned']) ||
            ($this->_server->getCurrentEntitySetting('WantAuthnRequestsSigned', false))) {
            $this->_verifySignatureMessage($request, self::KEY_REQUEST);
        }
        
        $this->_verifyMessageDestinedForUs($request['message']);
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
        if ($this->_server->getCurrentEntitySetting('WantAssertionsSigned', true)) {
            $this->_verifySignatureMessage($response, self::KEY_RESPONSE);
        }
        $this->_verifyMessageDestinedForUs($response['message']);
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
            $message['message']
        );

        if (!isset($message['message']['saml:Assertion'])) {
            return $messageVerified;
        }

        $assertionVerified = $this->_verifySignatureXMLElement(
            $remoteEntity['certificates']['public'],
            $message['MessageRaw'],
            $message['message']['saml:Assertion']
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
                throw new Corto_Module_Bindings_VerificationException("Destination: '$destinationId' is not here");
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

    function soapRequest($soapServiceUrl, array $body)
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

    function soapResponse(array $body)
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
}
