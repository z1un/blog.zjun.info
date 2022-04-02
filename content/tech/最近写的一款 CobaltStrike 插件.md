---
title: "最近写的一款 CobaltStrike 插件"
slug: z1-aggressorscripts
aliases: ["/2020/z1-aggressorscripts.html"]
date: 2020-11-19 12:50:05
categories: ["安全工具"]
tags: ["AggressorScripts", "内网渗透", "CobaltStrike"]
toc: true
draft: false
---

Cobalt Strike 扩展性强，但是目前集成化插件很少，且大部分不满足个人内网渗透需求，所以有了本篇内容。本文不再更新但是 github 插件仓库将长期更新。

## [Z1-AggressorScripts](https://github.com/z1un/Z1-AggressorScripts)

2020.11.21 更新：

* 辅助模块的 zip 打包更换成 uknow 师傅的[SharpZip](https://github.com/uknowsec/SharpZip)，内存加载无需上传。
* 权限维持模块新增创建自启动运行，包括添加注册表，添加启动文件夹，创建启动服务三种方式。

  2020.11.20 更新：

* 内网穿透模块新增支持 nps。

* frp 由之前的 upx 压缩版本换成未压缩版，upx 压缩后的 frp32 位和 nps 都会在 360 上报毒，索性全部换成原版。但是这就项目导致体积由 20 几 M 增加到了 30 几 M，强烈建议到[gitee](https://gitee.com/z1un/Z1-AggressorScripts)下载发行版压缩文件。

  windows-npc64 位通过 cs 上传后运行会报错，不知道是不是我个人环境问题，所以 npc 只上传 32 位，不影响使用。

适用于 Cobalt Strike 3.x & 4.x 的插件。

![image-20201119120243146](https://oss.zjun.info/zjun.info/20201119120244.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

## 提权

01. [watson](https://github.com/rasta-mouse/Watson)获取可提取漏洞
02. [sweetpotato](https://github.com/CCob/SweetPotato)
03. juicypotato
04. MS14-058
05. MS15-051
06. MS16-016
07. MS16-032
08. MS16-135
09. CVE-2020-0796
10. [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC)

## 信息搜集

01. 单机常用命令

* systeminfo
* whoami /all
* ipconfig /all
* 查看路由表
* 查看 arp 缓存
* 查看用户信息
* 查看安装程序和版本信息
* 查看安装的补丁
* 查看运行的进程及路径
* 查看进程详细信息
* 查看服务
* 查看防火墙配置
* 查看计划任务
* 查看启动程序信息
* 查看在线用户
* 查看开机时间
* 查看 powershell v5 历史命令
* 查看最近使用的项目
* 查看 SMB 指向路径

02. 域环境常用命令

* [AdFind](http://www.joeware.net/freetools/tools/adfind/index.htm)

  * 列出域控制器名称
  * 查询当前域中在线的计算机
  * 查询当前域中在线的计算机 (只显示名称和操作系统)
  * 查询当前域中所有计算机
  * 查询当前域中所有计算机 (只显示名称和操作系统)
  * 查询域内所有用户
  * 查询所有 GPO

* 查询域
* 查看域管
* 查看域用户详细信息
* 查看当前登陆域
* 查看时间服务器
* 显示当前域的计算机列表
* 查看登陆本机的域管
* 查看所有域用户
* 查看域内所有用户组列表
* 查看主域控制器
* 查看域控列表
* 查看域控主机名
* 获取域信任信息
* 获取域密码信息
* 查看所有域成员计算机列表
* 查看域内所有计算机

03. [SharpChassisType](https://github.com/RcoIl/CSharp-Tools/tree/master/SharpChassisType)判断主机类型

   用于判断当前机器类型（桌面计算机、笔记本等判断）。

04. [SharpNetCheck](https://github.com/uknowsec/SharpNetCheck)探测出网

   在渗透过程中，对可以出网的机器是十分渴望的。在收集大量弱口令的情况下，一个一个去测试能不能出网太麻烦了。所以就有了这个工具，可配合如 wmiexec、psexec 等横向工具进行批量检测，该工具可以在 dnslog 中回显内网 ip 地址和计算机名，可实现内网中的快速定位可出网机器。

05. [SharpEventLog](https://github.com/uknowsec/SharpEventLog)(获取系统登录日志，快速定位运维机)

   读取登录过本机的登录失败或登录成功（4624，4625）的所有计算机信息，在内网渗透中快速定位运维管理人员。

06. [SharpCheckInfo](https://github.com/uknowsec/SharpCheckInfo)(获取多项主机信息)

   收集目标主机信息，包括最近打开文件，系统环境变量和回收站文件等等。

07. [SharpSQLDump](https://github.com/uknowsec/SharpSQLDump)(快速列出数据库数据)

   内网渗透中快速获取数据库所有库名，表名，列名。具体判断后再去翻数据，节省时间。适用于 mysql，mssql。

08. [SharpClipHistory](https://github.com/FSecureLABS/SharpClipHistory)(获取 win10 剪切板)

   可用于从 1809 Build 版本开始读取 Windows 10 中用户剪贴板历史记录的内容。

09. [SharpAVKB](https://github.com/uknowsec/SharpAVKB)(杀软和补丁对比)

   Windows 杀软对比和补丁号对比。

10. [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker)(获取 EDR 信息)
    检查正在运行的进程，进程元数据，加载到当前进程中的 Dll 以及每个 DLL 元数据，公共安装目录，已安装的服务和每个服务二进制元数据，已安装的驱动程序和每个驱动程序元数据，所有这些都存在已知的防御性产品，例如 AV，EDR 和日志记录工具。

11. [SharpDir](https://github.com/jnqpblc/SharpDir)(文件搜索)
    可在本地和远程文件系统中搜索文件。

12. [Everything](https://www.voidtools.com/zh-cn/)(建立 http 服务文件搜索)

## 定位域管

01. [PsLoggedon](https://docs.microsoft.com/zh-cn/sysinternals/downloads/psloggedon)

   微软官方工具。

02. [PVEFindADUser](https://github.com/chrisdee/Tools/tree/master/AD/ADFindUsersLoggedOn)

   可用于查找 Active Directory 用户的登录位置和/或查找谁在特定计算机上登录。这应该包括本地用户，通过 RDP 登录的用户，用于运行服务和计划任务的用户帐户。

03. [netview](https://github.com/mubix/netview)

   Netview 是枚举工具。它使用（带有-d）当前域或指定的域（带有-d 域）来枚举主机。如果希望指定包含主机列表的文件，也可以使用-f。您希望排除的任何主机名都可以在带有-e 的列表中指定。如果要查询域组并突出显示这些用户的登录位置，请使用-g 指定该组。

## 读取密码

01. logonpasswords

02. Krbtgt hash

03. 探测 wifi 密码

* 获取连接过的 wifi

* 获取 wifi 密码

* [SharpWifiGrabber](https://github.com/r3nhat/SharpWifiGrabber)(检索 Wi-Fi 密码)

     Sharp Wifi Password Grabber 以明文形式从保存在工作站上的所有 WLAN 配置文件中检索 Wi-Fi 密码。

04. 修改注册表 dump 明文密码

* 显示明文
* 强制锁屏
* 隐藏明文

05. 提取浏览器数据及密码

* [BrowserGhost](https://github.com/QAX-A-Team/BrowserGhost)(提取浏览器密码)

     奇安信出品。这是一个抓取浏览器密码的工具，后续会添加更多功能

* [SharpChromium](https://github.com/djhohnstein/SharpChromium)(提取浏览器数据)

     用于检索 Chromium 数据，例如 Cookie，历史记录和保存的登录名。

* [SharpWeb](https://github.com/djhohnstein/SharpWeb)(提取浏览器数据)

     可从 Google Chrome，Mozilla Firefox 和 Microsoft Internet Explorer / Edge 检索保存的浏览器凭据。

06. 本地程序文件密码解密

* [SharpCloud](https://github.com/chrismaddalena/SharpCloud)(获取云凭证)

     用于检查是否存在与 AWS，Microsoft Azure 和 Google Compute 相关的凭证文件。

* [SharpDecryptPwd](https://github.com/uknowsec/SharpDecryptPwd)(from uknowsec)

     对密码已保存在 Windwos 系统上的部分程序进行解析，包括：Navicat,TeamViewer,FileZilla,WinSCP,Xmangager 系列产品（Xshell,Xftp)。

* [SharpDecryptPwd](https://github.com/RcoIl/SharpDecryptPwd)(from RcoIl)

     该程序主要是针对已保存在 Windows 系统上的程序密码进行解密。目前支持 Navicat 系列、Xmanager 系列、TeamViewer、FileZilla 客户端、Foxmail、RealVNC 服务端、TortoiseSVN、WinSCP、Chrome 全版本。

07. 钓鱼密码窃取

* [FakeLogonScreen](https://github.com/bitsadmin/fakelogonscreen)(windows 锁屏钓鱼)

     FakeLogonScreen 是用于伪造 Windows 登录屏幕以获取用户密码的实用程序。输入的密码已针对 Active Directory 或本地计算机进行了验证，以确保密码正确，然后将其显示在控制台上或保存到磁盘。

* [CredPhisher](https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher)(认证登录框钓鱼)

     使用 CredUIPromptForWindowsCredentialsWinAPI 函数提示当前用户提供其凭据。支持一个参数以提供将显示给用户的消息文本。

## 内网扫描

01. [SharpWebScan](https://github.com/RcoIl/CSharp-Tools/tree/master/SharpWebScan)(探测 web 服务)

   扫描 C 段 的 Web 应用，获取 Title，可自定义多端口。外网也非常好用

02. [TailorScan](https://github.com/uknowsec/TailorScan)(缝合怪内网扫描器)

   缝合怪内网扫描器，支持端口扫描，识别服务，获取 title，扫描多网卡，ms17010 扫描，icmp 存活探测。

03. [fscan](https://github.com/shadow1ng/fscan)(一键大保健)

   一款内网扫描工具，方便一键大保健。支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis 批量写私钥、计划任务反弹 shell、读取 win 网卡信息等。

04. [crack](https://github.com/oksbsb/crack)爆破

   爆破工具，支持 ftp ssh smb mysql mssql postgres。

05. [SharpSpray](https://github.com/jnqpblc/SharpSpray)(域内密码爆破)

## RDP 相关

01. 查看 RDP 端口
02. 探测 RDP 服务是否开启
03. 开启 RDP 服务
04. 关闭 RDP 服务
05. 添加防火墙放行 RDP 规则

## 添加用户

01. 激活 guest 用户

02. 添加域管用户

03. 创建管理员用户

04. [add-admin](https://github.com/lengjibo/RedTeamTools/blob/master/windows/bypass360%E5%8A%A0%E7%94%A8%E6%88%B7/README.md)添加用户 bypass

   执行后自动添加一个账户进入管理员组。
   帐号：hacker 密码：P@ssw0rd

## 内网穿透

01. [frpmodify](https://github.com/uknowsec/frpModify)无需 frpc.ini 落地

   frp 指定参数版（无需 frpc.ini 落地）

02. [nps](https://github.com/ehang-io/nps)无配置文件落地

   一款轻量级、高性能、功能强大的内网穿透代理服务器。支持 tcp、udp、socks5、http 等几乎所有流量转发。使用参考：<https://mp.weixin.qq.com/s/zI04_kxVFWdnegctAzNmmg>。

03. [NATBypass](https://github.com/cw1997/NATBypass)端口转发

   一款 lcx（htran）在 golang 下的实现。
   通过主动连接具有公网 IP 的电脑打通隧道可实现内网穿透，让内网主机提供的服务能够借助外网主机来访问。软件实现的端口转发，透明代理，在主机限制入站规则但未限制出站规则的特定情况下可绕过防火墙。

04. [iox](https://github.com/EddieIvan01/iox)端口转发与 socks5 隧道

   golang 实现，端口转发和内网代理工具，功能类似于 lcx/ew，但是比它们更好。

## 权限维持

01. Skeleton Key
02. 白银票据
03. 黄金票据

## 日志清除

清除系统日志

```bash
wevtutil cl security
wevtutil cl system
wevtutil cl application
wevtutil cl "windows powershell"
```

## 辅助模块

01. certutil 下载文件

```bash
   certutil.exe -urlcache -split -f $url $path
   ```

02. vbs 下载文件

   vbs 脚本远程下载文件，命令行传参，执行完毕自动清除 vbs 下载脚本。

03. [EncryptedZIP](https://github.com/mnipper/EncryptedZip)(压缩文件)

   对目录或文件进行加密压缩，使用 AES-256，使用大约 100 个字符的随机生成的 base64 密码对文件进行加密。根据提供的公共密钥对密码进行加密。压缩包提取到本地需要用 EncryptedZIP 解密。

04. [SharpOSS](https://github.com/uknowsec/SharpOSS)(上传文件)

   “内网渗透的本质是信息收集”，尝尝会收集到一些体积较大的文件或者是源码进行分析利用。而网络情况复杂的情况下，通过菜刀一类 webshell 管理工具或 CS 一类 C2 工具来进行传输文件是非常慢的，而且 aliyunOSS 是白域名，比 cs 传输文件更为隐秘。所以会用到 AliyunOSS 来进行快速文件传输。所以就看了一下 aliyun-oss-csharp-sdk 实现了这个功能。

## 关于

[项目地址](https://github.com/z1un/Z1-AggressorScripts)

[zjun's blog](https://blog.zjun.info)

该项目借鉴了大量其他该类型优秀项目，所有工具皆来自互联网，并都有标注来源。不保证其安全性。

长期更新。
