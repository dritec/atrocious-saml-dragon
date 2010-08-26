<?php

require "Interface.php";

class Corto_Log_Dummy implements Corto_Log_Interface
{
    public function __construct()
    {
    }
    
    public function setId($id) 
    {
    }

	public function debug($message) 
	{
	}
	
    public function err($message)
    {
    }

    public function warn($message)
    {
    }
}
