<?php
/****************************************************************************
* Software: FPDF_Protection                                                 *
* Version:  1.05                                                            *
* Date:     2015-12-06                                                      *
* Author:   Klemen VODOPIVEC                                                *
* License:  FPDF                                                            *
*                                                                           *
* Thanks:  Cpdf (http://www.ros.co.nz/pdf) was my working sample of how to  *
*          implement protection in pdf.                                     *
****************************************************************************/

require('fpdf.php');

if (function_exists('mcrypt_encrypt'))
{
    function RC4($key, $data)
    {
        return mcrypt_encrypt(MCRYPT_ARCFOUR, $key, $data, MCRYPT_MODE_STREAM, '');
    }
}
else
{
    function RC4($key, $data)
    {
        static $last_key, $last_state;

        if($key != $last_key)
        {
            $k = str_repeat($key, 256/strlen($key)+1);
            $state = range(0, 255);
            $j = 0;
            for ($i=0; $i<256; $i++){
                $t = $state[$i];
                $j = ($j + $t + ord($k[$i])) % 256;
                $state[$i] = $state[$j];
                $state[$j] = $t;
            }
            $last_key = $key;
            $last_state = $state;
        }
        else
            $state = $last_state;

        $len = strlen($data);
        $a = 0;
        $b = 0;
        $out = '';
        for ($i=0; $i<$len; $i++){
            $a = ($a+1) % 256;
            $t = $state[$a];
            $b = ($b+$t) % 256;
            $state[$a] = $state[$b];
            $state[$b] = $t;
            $k = $state[($state[$a]+$state[$b]) % 256];
            $out .= chr(ord($data[$i]) ^ $k);
        }
        return $out;
    }
}

class FPDF_Protection extends FPDF
{
    var $encrypted = false;  //whether document is protected
    var $Uvalue;             //U entry in pdf document
    var $Ovalue;             //O entry in pdf document
    var $Pvalue;             //P entry in pdf document
    var $enc_obj_id;         //encryption PDF object id
    var $enc_algorithm;      //Encryption algorithm, RC4 or AES
    var $enc_security_handler; //Security handler version, 2 for basic, 3 for AES and 40+ bits
    var $enc_key;            //Key used for encryption
    var $enc_key_len;        //Number of bytes used for encryption key
    var $id;                 //Document ID

    /**
    * Function to set permissions as well as user and owner passwords
    *
    * - permissions is an array with values taken from the following list:
    *   copy, print, modify, annot-forms
    *   If a value is present it means that the permission is granted
    * - If a user password is set, user will be prompted before document is opened
    * - If an owner password is set, document can be opened in privilege mode with no
    *   restriction if that password is entered
    */
    function SetProtection($permissions=array(), $user_pass='', $owner_pass=null)
    {
        $options = array('print' => 4, 'modify' => 8, 'copy' => 16, 'annot-forms' => 32 );
        $protection = 192;
        foreach($permissions as $permission)
        {
            if (!isset($options[$permission]))
                $this->Error('Incorrect permission: '.$permission);
            $protection += $options[$permission];
        }
        $this->enc_key_len = 5;
        $this->id = uniqid().__FILE__.rand();

        if ($owner_pass === null)
            $owner_pass = uniqid(rand());

        $this->encrypted = true;
        $this->_setOvalue($owner_pass, $user_pass);
        $this->_setEncryptionKey($user_pass, $protection);
        $this->_setUvalue();
        $this->_setPvalue($protection);
    }

    /****************************************************************************
    *                                                                           *
    *                              Private methods                              *
    *                                                                           *
    ****************************************************************************/

    function _putstream($s)
    {
        if ($this->encrypted)
            $s = RC4($this->_objectkey($this->n), $s);
        parent::_putstream($s);
    }

    function _textstring($s)
    {
        if (!$this->_isascii($s))
            $s = $this->_UTF8toUTF16($s);
        if ($this->encrypted)
            $s = RC4($this->_objectkey($this->n), $s);
        return '('.$this->_escape($s).')';
    }

    /**
    * Compute key depending on object number where the encrypted data is stored
    */
    function _objectkey($n)
    {
        $key = $this->enc_key.pack('VXxx', $n);
        $len = $this->enc_key_len + 5;
        return substr($this->_md5_16($key),0,$len);
    }

    function _putresources()
    {
        parent::_putresources();
        if ($this->encrypted) {
            $this->_newobj();
            $this->enc_obj_id = $this->n;
            $this->_put('<<');
            $this->_putencryption();
            $this->_put('>>');
            $this->_put('endobj');
        }
    }

    function _putencryption()
    {
        $this->_put('/Filter');
        $this->_put('/Standard');
        $this->_put('/V 1');
        $this->_put('/R 2');
        $this->_put('/O ('.$this->_escape($this->Ovalue).')');
        $this->_put('/U ('.$this->_escape($this->Uvalue).')');
        $this->_put('/P '.$this->Pvalue);
    }

    function _puttrailer()
    {
        parent::_puttrailer();
        if ($this->encrypted) {
            $id = md5($this->id);
            $this->_put('/Encrypt '.$this->enc_obj_id.' 0 R');
            $this->_put('/ID [ <'.$id.'> <'.$id.'> ]');
        }
    }

    /**
    * Get MD5 as 16 byte binary string
    */
    function _md5_16($string)
    {
        return pack('H*',md5($string));
    }

    function _pad($string,$len=0)
    {
        $padding = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08".
                   "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
        if ($len == 0)
        {
            $len = strlen($padding);
        }
        return substr($string.$padding,0,$len);
    }

    /**
    * Compute O (owner password) value
    *
    * Depends on following member variables:
    * - enc_key_len
    */
    function _setOvalue($owner_pass, $user_pass)
    {
        $key = $this->_md5_16( $this->_pad($owner_pass, 32) );
        $key = substr($key,0,$this->enc_key_len);
        $encrypted = RC4($key, $this->_pad($user_pass, 32) );
        $this->Ovalue = $encrypted;
    }

    /**
    * Compute U (user password) value
    *
    * Depends on following member variables:
    * - enc_key
    * - enc_key_len
    */
    function _setUvalue()
    {
        $padding = $this->_pad('',32);
        $encrypted = RC4($this->enc_key, $padding);
        $this->Uvalue = $encrypted;
    }

    /**
     * Set Pvalue
     */
    function _setPvalue($protection)
    {
        $this->Pvalue = -(($protection^255)+1);
    }

    /**
    * Compute encryption key
    *
    * Depends on following member variables:
    * - Ovalue
    * - enc_key_len
    */
    function _setEncryptionKey($user_pass, $protection)
    {
        $user_pass = $this->_pad($user_pass,32);
        $id = $this->_md5_16($this->id);
        $hash = $this->_md5_16($user_pass.$this->Ovalue.pack("V", $protection | 0xFFFFFF00).$id);

        $this->enc_key = substr($hash,0,$this->enc_key_len);
    }
}

?>
