<?php

/**
 * Array with remote servers, each server has the URL it is hosted on as array key.
 * example:
 * $remoteEntities = array('http://remote_idp.example.com'=>...));
 *
 * As value it can have an array with one or more of the following configuration options:
 *
 * - SharedKey
 * Shared secret used to sign the message
 *
 * - spfilter
 *
 * - AssertionConsumerServiceLocation
 * For SPs: Location where the SAML2 Response Assertion should be sent to
 * (note that because we are a proxy we don't care about binding, if we're given an assertion with HTTP-POST,
 * then we send it with HTTP-POST)
 *
 * - SingleSignOnServiceLocation
 * For IdPs: Location where the SAML2 Authntication Request should be sent to
 * (note that because we are a proxy we don't care about binding, if we're given an request with HTTP-Redirect,
 * then we send it with HTTP-Redirect)
 *
 * - ArtifactResolutionServiceLocation
 * Location where SAML2 Artifacts can be resolved.
 *
 * - filter
 * Called when we receive an Assertion with attributes and when we send that Assertion to the SP
 * NOTE: Called twice per assertion!
 *
 * - Certificates
 *   - Public
 *
 * - WantsAuthnRequestsSigned
 * For IdPs: Wants the authentication requests signed
 *
 * - WantsResponsesSigned
 * For SPs: Wants the (assertion) response signed
 *
 * - WantsJson
 * Wants message in JSON format, not in XML.
 *
 * @var $entities
 */

$remoteEntities = array(

);