<?php
/**
 * Created by PhpStorm.
 * User: freek
 * Date: Nov 23, 2010
 * Time: 8:37:01 PM
 * To change this template use File | Settings | File Templates.
 */

class GoogleFilter {

    static function google($params)
    {
        $acs = $params['cortodata']['response']['_Destination'];
        $assertion = &$params['cortodata']['response']['saml:Assertion'];
        $samlattribute = $assertion['saml:AttributeStatement'][0]['saml:Attribute'];
        $attributes = attributes2array($samlattribute);
        $mail = 'freek'; #@g.wayf.dk'; #$attributes['uid'][0] . '@g.wayf.dk';
        $assertion['_ID'] = "z" . sha1(uniqid(mt_rand(), true));
        unset($assertion['saml:AttributeStatement']);
        unset($assertion['ds:Signature']);
        unset($assertion['saml:AuthnStatement']['saml:AuthnContext']['saml:AuthenticatingAuthority']);

        $assertion['saml:Subject']['saml:NameID'] = Array(
            '_Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            '_SPNameQualifier' => "google.com",
            '__v' => $mail,
        );


        $assertion['saml:Conditions']
        ['saml:AudienceRestriction']['saml:Audience']['__v'] = $acs;
        $assertion['saml:Subject']['saml:SubjectConfirmation']['saml:SubjectConfirmationData']['_Recipient']
                = $acs;

        return $params['cortodata'];
    }
}