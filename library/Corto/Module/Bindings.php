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
                'saml:Issuer'   => array('__v' => $this->_server->getCurrentHostedEntityUrl()),
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

        $message = base64_decode($_POST[$key]);
        $relayState = $_POST['RelayState'];
        
        return array(
            'Message' => $message,
            'RelayState' => $relayState
        );
    }

    protected function _receiveMessageFromHttpRedirect($key)
    {
        if (!isset($_GET[$key])) {
            return false;
        }

        $message = gzinflate(base64_decode($_GET[$key]));
        $relayState         = $_GET['RelayState'];
        $signature          = $_GET['Signature'];
        $signingAlgorithm   = $_GET['SigAlg'];

        return array(
            'Message'           => $message,
            'RelayState'        => $relayState,
            'Signature'         => $signature,
            'SigningAlgorithm'  => $signingAlgorithm,
        );
    }

    protected function _verifyRequest(array $request)
    {
        $this->_verifyMessageDestinedForUs($request['message']);
    }

    protected function _decryptResponse(array $response)
    {
        
    }

    protected function _verifyResponse(array $response)
    {
        $this->_MessageDestinedForUs($response['message']);
    }

    protected function _verifyMessageDestinedForUs(array $message)
    {
        $destinationId = $message['_Destination'];
        if ($destinationId) { // Destination is optional
            if (strpos($this->_server->getCurrentHostedEntityUrl(), $destinationId) !== 0) {
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
