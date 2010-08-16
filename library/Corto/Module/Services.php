<?php

class Corto_Module_Services_Exception extends Corto_ProxyServer_Exception
{
}

class Corto_Module_Services extends Corto_Module_Abstract
{
    /**
     * Handle a Single Sign On request (Authentication Request)
     */
    public function singleSignOnService()
    {
        $request = $this->_server->getBindingsModule()->receiveRequest();


        // Add the hosted IdP as a scoped IdP
        $scopedIDPs = array();
        $presetIdP = $this->_server->getConfig('idp');
        if ($presetIdP) {
            $scopedIDPs[] = $presetIdP;
        }

        // If ForceAuthn attribute is on, then remove cached responses and cached IDPs
        if (isset($request['_ForceAuthn'])) {
            $this->_server->getSessionLog()->debug('SSO: Forcing new authentication, cached responses removed');
            unset($_SESSION['CachedResponses']);
        }

        // Add scoped IdPs (allowed IDPs for reply) from request to allowed IdPs for responding
        if (isset($request['samlp:Scoping']['samlp:IDPList']['samlp:IDPEntry'])) {
            foreach ($request['samlp:Scoping']['samlp:IDPList']['samlp:IDPEntry'] as $IDPEntry) {
                $scopedIDPs[] = $IDPEntry['_ProviderID'];
            }
        }

        // If one of the scoped IDP has a cache entry, return that
        $cachedIDPs = array();
        if (isset($_SESSION['CachedResponses'])) {
            $cachedIDPs = array_keys((array) $_SESSION['CachedResponses']); 
        }

        if ($commonIDPs = array_intersect($cachedIDPs, $scopedIDPs) || (sizeof($scopedIDPs) == 0 && $commonIDPs = $cachedIDPs)) {
            $this->_server->getSessionLog()->debug("SSO: Cached response found");
            $cachedResponse = $_SESSION['CachedResponses'][$commonIDPs[0]];
            $response = $this->_server->createEnhancedResponse($request, $cachedResponse);
            return $this->_server->sendResponse($request, $response);
        }

        // If the scoped proxycount = 0, respond with a ProxyCountExceeded error
        if (isset($request['samlp:Scoping']['_ProxyCount']) && $request['samlp:Scoping']['_ProxyCount'] == 0) {
            $this->_server->getSessionLog()->debug("SSO: Proxy count exceeded!");
            $response = $this->_server->createErrorResponse($request, 'ProxyCountExceeded');
            return $this->_server->sendResponse($request, $response);
        }

        // If we configured an allowed IdP and an IDPList then we ignore the original scoping rules
        // and send the new authnrequest
        $presetIdPs = $this->_server->getCurrentEntitySetting('IdPList');
        if ($presetIdP && $presetIdPs) {
            $this->_server->getSessionLog()->debug("SSO: Preset idp and idpList found");
            return $this->_server->sendAuthenticationRequest($request, $presetIdP, $presetIdPs);
        }

        // If we have an IdP configured then we send the authentication request to that IdP
        if ($presetIdP) {
            $this->_server->getSessionLog()->debug("SSO: Preset idp found");
            return $this->_server->sendAuthenticationRequest($request, $presetIdP);
        }

        // Get all registered Single Sign On Services
        $candidateIDPs = array();
        foreach ($this->_server->getRemoteEntities() as $remoteEntityId => $remoteEntity) {
            if (isset($remoteEntity['SingleSignOnService'])) {
                $candidateIDPs[] = $remoteEntityId;
            }
        }

        // Filter out the hosted entity and if we have scoping, filter out every non-scoped IdP
        $candidateIDPs = array_diff($candidateIDPs, array($this->_server->getCurrentEntityUrl()));
        $candidateIDPs = sizeof($scopedIDPs) > 0 ? array_intersect($scopedIDPs, $candidateIDPs) : $candidateIDPs;

        // More than 1 candidate found, send authentication request to the first one
        if (count($candidateIDPs) === 1) {
            $this->_server->getSessionLog()->debug("SSO: Only 1 candidate IdP");
            $idp = $candidateIDPs[0];
            return $this->_server->sendAuthenticationRequest($request, $idp);
        }

        // No IdPs found! Send an error response back.
        if (count($candidateIDPs) === 0) {
            $this->_server->getSessionLog()->debug("SSO: No Supported Idps!");
            $response = $this->_server->createErrorResponse($request, 'NoSupportedIDP');
            return $this->_server->sendResponse($request, $response);
        }

        // > 1 IdPs found, but isPassive attribute given, unable to respond
        if (isset($request['_IsPassive']) && $request['_IsPassive'] === 'true') {
            $this->_server->getSessionLog()->debug("SSO: IsPassive with multiple IdPs!");
            $response = $this->_server->createErrorResponse($request, 'NoPassive');
            return $this->_server->sendResponse($request, $response);
        }

        // Store the request in the session
        $id = $request['_ID'];
        $_SESSION[$id]['SAMLRequest'] = $request;

        // Show WAYF
        $this->_server->getSessionLog()->debug("SSO: Showing WAYF");
        return $this->showWayf($request, $candidateIDPs);
    }

    protected function showWayf($request, $candidateIdPs)
    {
        // Post to the 'continueToIdpService'
        $action = $this->_server->getCurrentEntityUrl('continueToIdP');

        $requestIssuer = $request['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($requestIssuer);

        $output = $this->_server->renderTemplate(
            'discover',
            array(
                'action'            => $action,
                'ID'                => $request['_ID'],
                'idpList'           => $candidateIdPs,
                'metaDataSP'        => $remoteEntity,
                'remoteEntities'    => $this->_server->getRemoteEntities(),
            ));
        $this->_server->sendOutput($output);
    }

    public function continueToIdP()
    {
        // Retrieve the request from the session.
        $request = $_SESSION[$_POST['ID']]['hSAMLRequest'];
        
        $this->_server->sendAuthenticationRequest($request, $_REQUEST['idp']);
    }

    public function assertionConsumerService()
    {        
        $response = $this->_server->getBindingsModule()->receiveResponse();

        $this->_server->filterInputAssertionAttributes($response);

        // Cache the response
        if ($this->_server->getCurrentEntitySetting('keepsession', false)) {
            $issuerEntityId = $response['saml:Issuer']['__v'];
            $_SESSION['CachedResponses'][$issuerEntityId] = $response;
        }

        $id = isset($_POST['target']) ? $_POST['target'] : $response['_InResponseTo'];
        if (!$id) {
            return $this->unsolicitedAssertionConsumerService();
        }

        if (!isset($_SESSION[$id])) {
            throw new Corto_Module_Services_Exception("Unknown id ($id) in POST target or InResponseTo attribute?!?");
        }

        $originalRequestId = $_SESSION[$id]['_InResponseTo'];
        if (!isset($_SESSION[$originalRequestId]['SAMLRequest'])) {
            throw new Corto_Module_Services_Exception('No origRequest: ' . $_SESSION[$id]['_InResponseTo']);
        }
        $originalRequest = $_SESSION[$originalRequestId]['SAMLRequest'];

        $response = $this->_server->createEnhancedResponse($originalRequest, $response);
        $this->_server->sendResponse($originalRequest, $response);
    }

    public function artifactResolutionService()
    {
        $postData = Corto_XmlToArray::xml2array(file_get_contents("php://input"));
        $artifact = $postData['SOAP-ENV:Body']['samlp:ArtifactResolve']['saml:Artifact']['__v'];

        $this->_server->restartSession(sha1($artifact), 'artifact');
        $message = $_SESSION['message'];
        session_destroy();

        $element = $message['__t'];
        $artifactResponse = array(
            'samlp:ArtifactResponse' => array(
                'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
                'xmlns:saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
                'ID' => $this->_server->getNewId(),
                'Version' => '2.0',
                'IssueInstant' => $this->_server->timeStamp(),
                'InResponseTo' => $postData['SOAP-ENV:Body']['samlp:ArtifactResolve']['_ID'],
                'saml:Issuer' => array('__v' => $GLOBALS['meta']['EntityID']),
                $element => $message,
            ),
        );
        $this->_server->getBindingsModule()->_soapResponse($artifactResponse);
    }
}