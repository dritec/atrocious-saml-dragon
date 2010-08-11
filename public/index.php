<?php

require '../library/Corto/ProxyServer.php';
$server = new Corto_ProxyServer();

$config = array();
require '../configs/config.inc.php';
$server->setConfigs($config);

$hostedEntities = array();
require '../configs/metadata.hosted.inc.php';
$server->setHostedEntities($hostedEntities);

$remoteEntities = array();
require '../configs/metadata.remote.inc.php';
$server->setRemoteEntities($remoteEntities);

$server->setTemplateSource(
    Corto_ProxyServer::TEMPLATE_SOURCE_FILESYSTEM,
    array(
        'path' => dirname(__FILE__) . '/../templates/')
);

$server->serveRequest($_SERVER['PATH_INFO']);