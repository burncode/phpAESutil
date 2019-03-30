<?php

require("./KeygenUtil.php");

$password="431598d084e55a9536e41a3f799a42b4";
$content='{"orderid":"10012018103100000014"}';
$keygenutil=new KeygenUtil();
echo "秘钥--->".$password;
echo "</br>";
echo "待加密明文--->".$content;
echo "</br>";
echo "加密结果:".$keygenutil->encryptAES($content,$password);
echo "</br>";
echo "-----------------------------------------------------";
echo "</br>";
echo "密文--->".$keygenutil->encryptAES($content,$password);
$decontent=$keygenutil->encryptAES($content,$password);
echo "</br>";
echo "解密结果:".$keygenutil->decryptAES($decontent,$password);

