<?php

namespace zvsv\crypt;

/**
 * Class cryptXor
 * Шифрование использующее побитовое сложение по модулю
 *
 * @package zvsv\crypt
 */
class cryptXor
{
    private $delimetr = 't.f-f.t';

    public function encriptEmail($email, $passw = false){
        if(!$email){
            return $email;
        }
        $email_arr = explode('@', $email);
        if(count($email_arr) !== 2){
            return $email;
        }
        $email_login = $email_arr[0];
        $length = mb_strlen($email_login);
        //Весь email шифровать нельзя, валидацию не пройдет, слишком длинный может получиться
        $length_crypt = ceil($length*0.4); //% логина шифруем (все что до @)
        $length_non_crypt = $length - $length_crypt; //Не шифрующиеся символы
        $email_crypt_part = substr($email_login, 0, $length_crypt);
        $email_non_crypt_part = $length_non_crypt > 0 ? substr($email_login, -1*$length_non_crypt) : '';

        return $this->encript($email_crypt_part, $passw).$this->delimetr.$email_non_crypt_part.'@'.$email_arr[1];
    }

    public function decriptEmail($email, $passw = false){
        $email_arr = explode('@', $email);
        if(count($email_arr) !== 2){
            return $email;
        }
        $email_login = $email_arr[0];
        $email_login_arr = explode($this->delimetr, $email_login);
        if(count($email_login_arr) !== 2){
            return $email;
        }
        return $this->decript($email_login_arr[0], $passw).$email_login_arr[1].'@'.$email_arr[1];
    }

    public function encript($msg, $passw = false){
        return bin2hex($this->strcode($msg, $passw));
    }

    public function decript($msg, $passw = false){
        return $this->strcode(hex2bin($msg), $passw);
    }

    protected function strcode($str, $passw){
        $passw = $passw ? $passw : "TF2017LaLa!54321";
        $salt = "Dn8*#2n!9j";
        $len = strlen($str);
        $gamma = '';
        $n = $len>100 ? 8 : 2;
        while( strlen($gamma)<$len )
        {
            $gamma .= substr(pack('H*', sha1($passw.$gamma.$salt)), 0, $n);
        }
        return $str^$gamma;
    }
}