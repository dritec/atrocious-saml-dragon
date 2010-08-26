<?php

require "Interface.php";

class Corto_Log_Dummy implements Corto_Log_Interface
{
	private $id;
	
    public function __construct()
    {
       openlog("Corto", LOG_PID | LOG_PERROR, LOG_LOCAL0);
    }
    
    public function setId($id) {
    	$this->id = $id;
    }

	public function debug($message) {
		syslog(LOG_DEBUG, $message);
	}
    public function err($message)
    {
    }

    public function warn($message)
    {
    }
}
