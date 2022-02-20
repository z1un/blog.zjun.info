---
title: "记录几个实战 Sql 注入绕过"
slug: record-several-actual-sql-bypasses
url: /2020/record-several-actual-sql-bypasses.html
date: 2020-03-25 12:50:05
categories: ["网络安全"]
tags: ["Web 渗透", "安全狗", "SQL 注入"]
toc: true
draft: false
---

前段时间的几次渗透测试中有几个有意思的 sql 注入，记录一下注入的绕过，网站地址及部分信息都有模糊处理，并已反映给相关单位。

## 0x01 案例一 绕安全狗

加 `'` ，报错，连 sql 语句都给了出来，典型的注入，原本以为属于可以直接一把梭的站

![sqlina-1](https://oss.zjun.info/zjun.info/sqlina-1.png)

`order by` 查字段遭遇安全狗拦截

![sqlina-2](https://oss.zjun.info/zjun.info/sqlina-2.png)

现在需要手动绕过，感觉这个安全狗应该是比较老的版本

过滤字符：

 `order by`

 `union select`

 `Length(database())`

......

不过滤单个字符，只过滤了相关组合查询语句，一番手动测试成功测出 `%23%0a` 可以绕过安全狗拦截

查字段 `payload` ：

 `%20order%23%0aby%2013%23`

`%23` ： `#`

`%0a` ： `换行符`

![sqlina-3](https://oss.zjun.info/zjun.info/sqlina-3.png)

根据是否报错，查询出有 `13` 个字段，但是当使用 `联合查询注入` 或 `盲注` 时这个 `payload` 失效，再次绕过安全狗

终极 `bypass` 如下，采用 `注释` 绕过，同时 `#` 必须用 `%23` ，不然会被安全狗拦截

 `/*&ID=-20 union select 1,2,3,4,5,6,7,8,9,10,11,12,13%23*/`

![sqlina-4](https://oss.zjun.info/zjun.info/sqlina-4.png)

## 0x02 案例二 盲注绕 WTS

查询字段很顺利，直接 `order by 2` 查出 `2个` 字段但是 `联合查询注入` 失败，各种绕过都试了下均失败

![sqlina-5](https://oss.zjun.info/zjun.info/sqlina-5.png)

又试了下盲注，居然过了，只是过程稍显麻烦

数据库长度为 `9`

 `and Length(database())>9%23`

然后 `burp` 抓包，设置爆破范围

![sqlina-6](https://oss.zjun.info/zjun.info/sqlina-6.png)

 `and ORD(mid(database(),1,1))=95%23`

设置 `AIISC` 范围 `95～122` ，因为 `mysql` 默认不区分大小写，默认都为小写，也可能存在数字或字符，所以也可以范围设宽 `33~126`

![sqlina-7](https://oss.zjun.info/zjun.info/sqlina-7.png)

一位一位爆库

![sqlina-8](https://oss.zjun.info/zjun.info/sqlina-8.png)

不再赘述。
