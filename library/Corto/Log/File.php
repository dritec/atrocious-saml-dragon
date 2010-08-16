<?php
 
class Corto_Log_File implements Corto_Log_Interface
{
    protected $_filePath;
    protected $_id;

    public function __construct($filePath)
    {
        $this->_filePath = $filePath;
    }

    public function setId($id)
    {
        $this->_id = $id;
        $this->_filePath .= '_' . $id;
    }

    public function err($message)
    {
        $this->_writeLine("[ERR] $message");
    }

    public function warn($message)
    {
        $this->_writeLine("[WARN] $message");
    }

    public function debug($message)
    {
        $this->_writeLine("[DBG] $message");
    }

    protected function _writeLine($line)
    {
        $handle = fopen($this->_filePath, 'a');
        fwrite($handle, $line . PHP_EOL);
        fclose($handle);
    }
}
