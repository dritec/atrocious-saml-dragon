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
        if ($GLOBALS['meta']['idp']) {
            $scopedIDPs[] = $GLOBALS['meta']['idp'];
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
            $response = $this->_server->createResponse($request, null, null, $_SESSION['CachedResponses'][$commonIDPs[0]]);
            $this->_server-> sendResponse($request, $response);
        }

        // If the scoped proxycount = 0, respond with a ProxyCountExceeded error
        if (isset($request['samlp:Scoping']['_ProxyCount']) && $request['samlp:Scoping']['_ProxyCount'] == 0) {
            $response = $this->_server->createResponse($request, 'ProxyCountExceeded');
            $this->_server->sendResponse($request, $response);
        }

        // If we configured an allowed IDPList then we ignore the original scoping rules
        // and add that one IDP as allowed IDP and send the new authnrequest
        if ($scope = $GLOBALS['meta']['IDPList']) {
            $this->_server->sendAuthnRequest($GLOBALS['meta']['idp'], $scope);
        }

        // If we have an IdP configured then we send the authentication request to that IdP
        if ($idp = $GLOBALS['meta']['idp']) {
            $this->_server->sendAuthnRequest($idp);
        }

        // If we have a virtual IdP defined (multiple IdPs that Corto merges into one), use that.
        if (isset($GLOBALS['meta']['virtual'])) {
            $this->handleVirtualIDP();
        }

        // Get all registered Single Sign On Services
        $candidateIDPs = array();
        foreach ($GLOBALS['metabase']['remote'] as $idp => $metaData) {
            if ($metaData['SingleSignOnService']) {
                $candidateIDPs[] = $idp;
            }
        }

        // Filter out the hosted entity and if we have scoping, filter out every non-scoped IdP
        $candidateIDPs = array_diff($candidateIDPs, array($GLOBALS['meta']['EntityID']));
        $candidateIDPs = sizeof($scopedIDPs) > 0 ? array_intersect($scopedIDPs, $candidateIDPs) : $candidateIDPs;

        // More than 1 candidate found, send authentication request to the first one
        if (count($candidateIDPs) === 1) {
            $this->_server->sendAuthnRequest($candidateIDPs[0]);
        }

        // No IdPs found! Send an error response back.
        if (count($candidateIDPs) === 0) {
            $response = $this->_server->createResponse($request, 'NoSupportedIDP');
            $this->_server->sendResponse($request, $response);
        }

        // discover should take are of IsPassive ...
        $this->discover($candidateIDPs);
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