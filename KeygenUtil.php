<?php

/**
 * AES加/解密文工具类
 * 利用php对java加解密工具类重新实现
 * @author    maohan
 * @copyright maohan
 * @version    1.0
 *
 */
class KeygenUtil{
    

    /**
	 * AES加密
	 * @param $content 待加密内容 
     * @param $keygen 秘钥       
	 * @return 密文
	 */
    public static function  encryptAES($content,$keygen){
		if ($content==null) {
			throw new Exception("加密内容不能为空");
        }
        $encryptResult = KeygenUtil::encrypt($content, $keygen);
		// BASE64位加密
        $encryptResultStr = KeygenUtil::ebotongEncrypto($encryptResult);
		return $encryptResultStr;
    }
    
    /**
	 * AES解密
	 * @param $encryptResultStr 密文  
     * @param $keygen 秘钥       
	 * @return 明文
	 */
	public static function  decryptAES($encryptResultStr,$keygen) {
		if ($encryptResultStr==null) {
			throw new Exception("加密内容不能为空");
		}
		// BASE64位解密
		try {
			$decrpt = KeygenUtil::ebotongDecrypto($encryptResultStr);
			$decryptResult =KeygenUtil::decrypt($decrpt, $keygen);
			return $decryptResult;
		} catch (Exception $e) { 
    // 当密文不规范时会报错，可忽略，但调用的地方需要考虑
			echo 'Message: ' .$e->getMessage();
		}
    }
    
    /**
     * 转换字符串为bytes
     * @param  $string 待转换字符串
     */
    public static function getBytes($string) {  
        $bytes = array();  
        for($i = 0; $i < strlen($string); $i++){  
             $bytes[] = ord($string[$i]);  
        }  
        return $bytes;  
    }  

    /**
	 * Base64加密字符串
     * 
	 * @param  $str 待加密字符串
	 */

	public  static function ebotongEncrypto($str) {
		if ( $str!=null && strlen($str) > 0) {
            utf8_encode($str);
            $result =base64_encode($str);
		}
        // base64加密超过一定长度会自动换行 需要去除换行符
        $patten = array("\r\n", "\n", "\r"); 
		return str_replace($patten,"",$result);
	}
 
	/**
	 * Base64解密字符串
	 * @param $str 待解密字符串 
	 */
	public static function ebotongDecrypto($str){
		$result =  base64_decode($str);
		return $result;
    }
    
    /**
     * @param $content    需要加密的内容
	 * @param $password    加密秘钥
     * @return $result     返回加密结果
	 *            
     */
    public  static function encrypt($content,$password){

        $key= KeygenUtil::keytool($password);
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
        $input = KeygenUtil::pkcs5_pad($content, $size);
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $key, $iv);
        $data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        $data = bin2hex($data);
        return $data;
    }

    private static function pkcs5_pad ($text, $blocksize) {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * @param $content    需要解密的内容
	 * @param $password    解密秘钥
     * @return $decrypted     返回解密结果
	 *            
     */
    public static function decrypt($content, $password) {
            $key= KeygenUtil::keytool($password);
            $decrypted= mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $key,
            KeygenUtil::hexToStr($content),
            MCRYPT_MODE_ECB
            );
     
        $dec_s = strlen($decrypted);
        $padding = ord($decrypted[$dec_s-1]);
        $decrypted = substr($decrypted, 0, -$padding);
        return $decrypted;
    }


    public static function parseHexStr2Str($hexStr)
    {
        $str = "";
        for ($i = 0, $size = strlen($hexStr) / 2; $i < $size; $i++) {
            $c = hexdec(substr($hexStr, $i * 2, 2));
            $str .= chr($c);
        }
        return $str;
    }
    /**
     * 16进制的转为2进制字符串         
     */   
    public static function hexToStr($hex)       
    {       
        $bin="";       
        for($i=0; $i<strlen($hex)-1; $i+=2)       
        {      
            $bin.=chr(hexdec($hex[$i].$hex[$i+1]));       
        }      
        return $bin;       
    }
    /**
     * java和php秘钥关系转换
     */
    private static function keytool($password){

        $key = substr(openssl_digest(openssl_digest($password, 'sha1', true), 'sha1', true), 0, 16);
        return $key;
    }
   
}
