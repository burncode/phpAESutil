# phpAESutil

php aes 加密解密工具类

对公司 java 相似工具类用 php 重写

## example

```php
<?php

require("./KeygenUtil.php");

$password="4334328d084e95ab536e41a3f499a42c4";
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

```
