<?php
 
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
        if ($request['_ForceAuthn']) {
            unset($_SESSION['CachedResponses']);
        }

        // Add scoped IdPs (allowed IDPs for reply) from request to allowed IdPs for responding
        if ($IDPList = $request['samlp:Scoping']['samlp:IDPList']['samlp:IDPEntry']) {
            foreach ($IDPList as $IDPEntry) {
                $scopedIDPs[] = $IDPEntry['_ProviderID'];
            }
        }

        // If one of the scoped IDP has a cache entry, return that
        $cachedIDPs = array_keys((array) $_SESSION['CachedResponses']);
        if ($commonIDPs = array_intersect($cachedIDPs, $scopedIDPs) || (sizeof($scopedIDPs) == 0 && $commonIDPs = $cachedIDPs)) {
            $cachedResponse = $_SESSION['CachedResponses'][$commonIDPs[0]];
            $response = $this->_server->createEnhancedResponse($request, $cachedResponse);
            return $this->_server->sendResponse($request, $response);
        }

        // If the scoped proxycount = 0, respond with a ProxyCountExceeded error
        if (isset($request['samlp:Scoping']['_ProxyCount']) && $request['samlp:Scoping']['_ProxyCount'] == 0) {
            $response = $this->_server->createErrorResponse($request, 'ProxyCountExceeded');
            return $this->_server->sendResponse($request, $response);
        }

        // If we configured an allowed IdP and an IDPList then we ignore the original scoping rules
        // and send the new authnrequest
        $presetIdPs = $this->_server->getCurrentEntitySetting('IdPList');
        if ($presetIdP && $presetIdPs) {
            return $this->_server->sendAuthenticationRequest($request, $presetIdP, $presetIdPs);
        }

        // If we have an IdP configured then we send the authentication request to that IdP
        if ($presetIdP) {
            return $this->_server->sendAuthenticationRequest($request, $presetIdP);
        }

        // If we have a virtual IdP defined (multiple IdPs that Corto merges into one), use that.
        if (isset($this->_server->getCurrentEntitySetting('virtual'))) {
            return $this->handleVirtualIDP();
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
            $idp = $candidateIDPs[0];
            return $this->_server->sendAuthenticationRequest($request, $idp);
        }

        // No IdPs found! Send an error response back.
        if (count($candidateIDPs) === 0) {
            $response = $this->_server->createErrorResponse($request, 'NoSupportedIDP');
            return $this->_server->sendResponse($request, $response);
        }

        // discover should take are of IsPassive ...
        return $this->showWayf($request, $candidateIDPs);
    }

    protected function showWayf($request, $candidateIdPs)
    {
        if ($request['_IsPassive'] === 'true') {
            $response = $this->_server->createErrorResponse($request, 'NoPassive');
            return $this->_server->sendResponse($request, $response);
        }

        $action = $this->_server->getCurrentEntityUrl('continueToIdP');

        $id = $request['_ID'];
        $_SESSION[$id]['SAMLRequest'] = $request;

        $requestIssuer = $request['saml:Issuer']['__v'];
        $remoteEntity = $this->_server->getRemoteEntity($requestIssuer);

        $output = $this->_server->renderTemplate(
            'discover',
            array(
                'action'            => $action,
                'ID'                => $id,
                'idpList'           => $candidateIdPs,
                'metaDataSP'        => $remoteEntity,
                'remoteEntities'    => $this->_server->getRemoteEntities(),
            ));
        $this->_server->sendOutput($output);
    }

    public function assertionConsumerService()
    {
        $response = $_REQUEST['hSAMLResponse'];
        $this->_server->inFilter($response);
        if (isset($GLOBALS['meta']['keepsession']) && $GLOBALS['meta']['keepsession']) {
            $_SESSION['CachedResponses'][$response['saml:Issuer']['__v']] = $response;
        }

        $id = isset($_POST['target']) ? $_POST['target'] : $response['_InResponseTo'];
        if (!$id) {
            $this->unsolicitedAssertionConsumerService();
        }

        if (!isset($_SESSION[$id])) {
            echo "Unknown id ($id) in InResponseTo attribute?!?";

            if (CORTO_TRACE) {
                echo "<br /><br />SESSION:<br /><pre>";
                var_dump($_SESSION);
                echo "</pre>";
            }
            exit;
        }

        if (!isset($_SESSION[$_SESSION[$id]['_InResponseTo']]['hSAMLRequest'])) {
            throw new Corto_ProxyServer_Exception('No origRequest: ' . $_SESSION[$id]['_InResponseTo']);
        }
        $originRequest = $_SESSION[$_SESSION[$id]['_InResponseTo']]['hSAMLRequest'];

        #unset($_SESSION[$id]['_InResponseTo']);
        $response = $this->_server->createResponse($originRequest, null, null, $response);

        $this->_server->sendResponse($originRequest, $response);
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
        $this->_server->getBindingsModule()->soapResponse($artifactResponse);
    }
}