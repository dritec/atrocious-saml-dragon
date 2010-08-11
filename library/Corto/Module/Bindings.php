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
    }

    public function receiveResponse()
    {
        $response = $this->_receiveMessage(self::KEY_RESPONSE);
        $this->_decryptResponse($response);
        $this->_verifyResponse($response);
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
                $message['__t'] = 'samlp:AuthnRequest';
            }
            else {
                return false;
            }
        }
        else if ($key === self::KEY_RESPONSE) {
            if (isset($artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest'])) {
                $message = $artifactResponse['samlp:ArtifactResponse']['samlp:AuthnRequest'];
                $message['__t'] = 'samlp:Response';
            }
            else {
                return false;
            }
        }

        $relayState = $_REQUEST['RelayState'];

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
        
    }

    protected function _verifyResponse(array $response)
    {
        if ($this->_server->getCurrentEntitySetting('WantAssertionsSigned', true)) {
            $this->_verifySignatureMessage($response, self::KEY_RESPONSE);
        }
        $this->_verifyMessageDestinedForUs($response['message']);
    }

    protected function _verifySignature(array $message, $key)
    {
        if (isset($message['Signature'])) { // We got a Signature in the URL (HTTP Redirect)
            return $this->_verifySignatureMessage($message, $key);
        }

        // Otherwise it's in the message or in the assertion in the message (HTTP Post Response)
        $requestIssuer = $request['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($requestIssuer);

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
