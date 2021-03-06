<?php


require_once 'Abstract.php';

/**
 * Service specific exception
 *
 */
class Corto_Module_Services_Exception extends Corto_ProxyServer_Exception {
}

/**
 * Services handles the actual SSO/SLO services:
 * - SingleSignonService
 * - SingleLogout
 * - AssertionConsumerService
 * - ArtifactResolutionService
 *
 * @throws Corto_Module_Services_Exception|Corto_ProxyServer_Exception
 *
 */

class Corto_Module_Services extends Corto_Module_Abstract {

    /**
     * Catch unknow services
     *
     * @throws Corto_ProxyServer_Exception
     * @param  $name
     * @param  $arguments
     * @return void
     */
    public function __call($name, array $arguments)
    {
        throw new Corto_Module_Services_Exception("No Service ($name) found for: " . print_r($arguments, 1));
    }

    /**
     * Handle an authentication request.
     *
     * @param  array $params
     * @return void
     *
     */

    public function singleSignOnService($params)
    {
        if ($this->_server->callfilters('init')) {

            $request = $this->_server->getBindingsModule()->receiveRequest($params);

            /**
             * We are always a proxy so if the scoped proxycount == 0, respond with a ProxyCountExceeded error
             * @todo register path length in cached responses and use in proxyCount check ??
             */

            if (nvl2($request, 'samlp:Scoping', '_ProxyCount') === 0) {
                $response = $this->_server->createErrorResponse($request, 'ProxyCountExceeded');
                return $this->_server->sendResponseToRequestIssuer($request, $response);
            }

            // Get all registered Single Sign On Services
            $candidateIDPs = $this->_server->getAllowedIdps();

            // No IdPs found! Send an error response back.
            if (empty($candidateIDPs)) {
                $response = $this->_server->createErrorResponse($request, 'NoSupportedIDP');
                return $this->_server->sendResponseToRequestIssuer($request, $response);
            }

            // If we configured an IDPList in metadata this is our primary scoping
            $scopedIDPs = $this->_server->getPresetIDPs();

            /**
             * Add scoping in request to configured scoping - this is NOT according to the spec
             * which says that you MUST append to a received IDPList
             */
            foreach ((array) nvl3($request, 'samlp:Scoping', 'samlp:IDPList', 'samlp:IDPEntry') as $IDPEntry) {
                $scopedIDPs[] = $IDPEntry['_ProviderID'];
            }

            // remove issuer + us from scope for use now ..
            $requesterIDs = array($params['EntityID'], $request['saml:Issuer']['__v']);

            // filter out already visited proxies (RequesterID) to prevent looping ...
            foreach ((array) nvl2($request, 'samlp:Scoping', 'samlp:RequesterID') as $requesterID) {
                $requesterIDs[] = $requesterID['__v'];
            }

            $relevantScopedIDPs = array_diff($scopedIDPs, $requesterIDs);

            // If we have scoping, filter out every non-scoped IdP
            $scopedCandidateIDPs = array_intersect($relevantScopedIDPs, $candidateIDPs);

            $state = array();
            $filters = $this->_server->getCurrentMD('IDP', 'corto:discoverfilter', null, array());
            if (!$filters) $filters = array('demoFilterClass::showWayf');
            $filterparams = array(
                'request' => $request,
                'scopedCandidateIDPs' => $scopedCandidateIDPs,
                'relevantScopedIDPs' => $relevantScopedIDPs,
                'server' => $this->_server,
            );
        }

        /* If we end up her we should show the wayf ... */

        if ($this->_server->callfilters("discovery", $state, $filters, $filterparams)) {
        }
    }

    /**
     * Handle a SingleLogout request/response
     *
     * @param  array $params
     * @return void
     *
     */

    public function SingleLogoutService(array $params)
    {
        $message = $this->_server->getBindingsModule()->receiveRequest($params);
        if ('samlp:LogoutRequest' == $message['__t']) {
            $this->_server->sloinit($message);
        } elseif ('samlp:LogoutResponse' == $message['__t']) {
            $this->_server->handleslo($message);
        } else {
            throw new Corto_Module_Services_Exception("Unknown message received at SigleLogoutService: " . print_r($message, 1));
        }
    }

    /**
     * Handle an authentication response and send it on to the SP.
     * Handle filtering for both incoming and outgoing response
     *
     * @throws Corto_Module_Services_Exception
     * @param  $params
     * @return void
     */

    public function assertionConsumerService($params)
    {
        if ($this->_server->callfilters('init')) {
            $receivedResponse = $this->_server->getBindingsModule()->receiveResponse($params);

// Get the ID of the Corto Request message
            if (!$receivedResponse['_InResponseTo']) {
                $message = "Unsollicited assertion (no InResponseTo in message) not supported!";
                throw new Corto_Module_Services_Exception($message);
            }

            $receivedRequest = $this->_server->getReceivedRequestFromResponse($receivedResponse['_InResponseTo']);
            $state = get_defined_vars();
            $filterparams = array('request' => $receivedRequest,
                                  'response' => $receivedResponse,
                                  'server' => $this->_server,);
            $filters = array_merge(
                $this->_server->getRemoteMD($receivedResponse['saml:Issuer']['__v'], 'IDP', 'corto:responseInputFilter', null, array()),
                $this->_server->getCurrentMD('SP', 'corto:responseOutputFilter', null, array()));
        }

// SP side filters

        if ($this->_server->callfilters("responsein", $state, $filters, $filterparams)) {
            extract($state);
            unset($state);
            $receivedResponse = $filterparams['response'];
            unset($filterparams);

            $proxySP = null;
            if ($proxyIDP = nvl($receivedRequest['__'], 'ProxyIDP')) {
                $proxySP = $params['EntityID'];
                $this->_server->setCurrentEntity($proxyIDP);
                $this->_server->startSession();
            }

            $_SESSION['cachedresponses'][$receivedResponse['saml:Issuer']['__v']] = $receivedResponse;
            $this->AssertionConsumerService2($receivedRequest, $receivedResponse, $proxySP);
        }
    }

    public function AssertionConsumerService2($receivedRequest = null, $receivedResponse = null, $proxySP = null)
    {

        if ($this->_server->callfilters('init')) {
            $receivedResponse = $this->_server->createEnhancedResponse($receivedRequest, $receivedResponse, $proxySP);
            $state = get_defined_vars();
            $filterparams = array('request' => $receivedRequest,
                                  'response' => $receivedResponse,
                                  'server' => $this->_server,);
            $filters = array_merge(
                $this->_server->getCurrentMD('IDP', 'corto:responseOutputFilter', null, array()),
                $this->_server->getRemoteMD($receivedRequest['saml:Issuer']['__v'], 'SP', 'corto:responseOutputFilter', null, array()));

            // IDP side filters
        }
        if ($this->_server->callfilters("responseout", $state, $filters, $filterparams, __FUNCTION__)) {
            extract($state);
            unset($state);
            $receivedResponse = $filterparams['response'];
            unset($filterparams);
            return $this->_server->sendResponseToRequestIssuer($receivedRequest, $receivedResponse);
        }
    }

    /**
     * Handle sending response by artifact
     *
     * @return void
     */

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

                'saml:Issuer' => array('__v' => $this->_server->getCurrentMD('entityID')),
                $element => $message,
            ),
        );
        $this->_server->getBindingsModule()->_soapResponse($artifactResponse);
    }

    /**
     * Sends metadata for the current entity;
     * Currently ignores the binding, as it its always URI
     * @return void
     */

    public function metadataservice()
    {
        header('Content-type: application/samlmetadata+xml');
        $entity = $this->_server->getCurrentMD('entityID');
        $md = $this->_server->getPublicMetadata($entity);
        print(Corto_XmlToArray::array2xml($md, 'md:EntityDescriptor'));
    }

}
