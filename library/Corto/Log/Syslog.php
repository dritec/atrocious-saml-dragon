<?php

require "Interface.php";

class Corto_Log_Syslog implements Corto_Log_Interface
{    
    public function __construct()
    {
        openlog("Corto", LOG_PID | LOG_PERROR, LOG_LOCAL0);
    }
    
    public function setId($id) 
    {
    }

    public function debug($message) 
    {
        syslog(LOG_DEBUG, $message);
    }
    public function err($message)
    {
        syslog(LOG_ERR, $message);
    }

    public function warn($message)
    {
        syslog(LOG_WARNING, $message);
    }
}
