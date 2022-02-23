---
title: "Bypass 域敏感组访问控制信息查询"
slug: bypass-domain-sensitive-group-acl-information-query
url: /2022/bypass-domain-sensitive-group-acl-information-query.html
date: 2022-02-23T21:15:45+08:00
categories: ["网络安全"]
tags: ["ACL", "访问控制", "域", "信息查询"]
toc: true
draft: false
---

内网域环境中，很多时候我们拿到的用户没有内网查询的权限，显示「发生系统错误，拒绝访问」比如以下这些命令：

```bash
net group "domain controllers" /domain
net group "domain computers" /domain
net group "domain admins" /domain
net group "domain users" /domain
net group "Enterprise Admins" /domain
...
```

![image-20220223140227556](https://oss.zjun.info/zjun.info/202202231403595.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

原因在于域管理员设置了访问控制 (ACL)，禁止指定用户对域内敏感组的读取，以此对域安全进行加固。

这里的敏感组包括，但不限于

* Domain Admins「指定的域管理员组」
* Domain Computers「加入到域中的所有工作站和服务器组」
* Domain Controllers「域中所有域控制器组」
* Domain Users「所有域用户组」
* Enterprise Admins「企业的指定系统管理员组」

## 配置 ACL 禁止域用户对敏感组的读取

企业域环境内会划分不同的组织单位 (Organizational Unit) 简称 OU，将不同部门的用户划入对应 OU，可以实现对不同部门更方便的管理设置不同的访问权限。比如在这里设置一个普通用户的 OU

![image-20220223141846098](https://oss.zjun.info/zjun.info/202202231419831.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

在这里可以添加域内同一级别的普通域用户，后续的权限管理配置就可以直接指定该 OU 进行配置（当然也可以指定单个用户），属于该组的成员将会继承其权限。接着将域用户 user1 和 user2 添加进普通用户组

![image-20220223152207327](https://oss.zjun.info/zjun.info/202202231522399.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

现在开始配置 ACL，比如 `Domain Admins` 组，先开启「查看」「高级功能」后，在「属性」选项卡中选择「安全」，点击「高级」

![image-20220223170504389](https://oss.zjun.info/zjun.info/202202231736163.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

再点击「添加」进行配置权限条目

![image-20220223170725729](https://oss.zjun.info/zjun.info/202202231736435.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

设置「主体」为刚才创建的普通用户组，也可以指定特定用户，「类型」选择拒绝，下面的权限可以看见默认已经勾选了「读取权限」，达到的效果就是「普通用户」组的所有用户都不能够读取 `Domain Admins` 组的信息。

![image-20220223170922096](https://oss.zjun.info/zjun.info/202202231735566.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

对于其他的组 ACL 配置与上面一致。

## 失败的查询

直接使用 `net group` 命令毫无疑问会拒绝访问

![image-20220223180254742](https://oss.zjun.info/zjun.info/202202231803679.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

下面试着通过 LDAP 协议的工具查询，比如：[ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)、ldapsearch 等。

> LDAP (Lightweight Directory Access Protocol)，轻量目录访问协议，是一种用来查询与更新 Active Directory 的目录服务通信协议。AD 域服务利用 LDAP 命名路径 (LDAP naming path) 来表示对象在 AD 内的位置，以便用它来访问 AD 内的对象。

通过 [ADExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) 虽然可以连接成功，但是里面对应组的信息却看不到

![image-20220223205222752](https://oss.zjun.info/zjun.info/202202232052784.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

利用 ldapsearch 查询，ldapsearch 是 kali 内置的工具，在 Ubuntu 或 Mac 下安装如下：

```bash
# Ubuntu 用户安装
sudo apt install ldap-utils

# mac 用户安装
brew install ldapvi
```

查询命令如下，部分可用，但是当查询对应组信息的时候就不行

```bash
# 查询所有域用户
ldapsearch -x -H ldap://172.16.86.136:389 -D "CN=user1,CN=Users,DC=zjun,DC=com" -w P@ssw0rd -b "DC=zjun,DC=com" "(&(objectClass=user)(objectCategory=person))" dn

# 查询域中所有机器
ldapsearch -x -H ldap://172.16.86.136:389 -D "CN=user1,CN=Users,DC=zjun,DC=com" -w P@ssw0rd -b "DC=zjun,DC=com" "(&(objectCategory=computer)(objectClass=computer))" dn

# 查询域控
ldapsearch -x -H ldap://172.16.86.136:389 -D "CN=user1,CN=Users,DC=zjun,DC=com" -w P@ssw0rd -b 'ou=domain controllers,dc=zjun,dc=com' 'objectClass=computer' dn

# 查询 domain admins 组
ldapsearch -x -H ldap://172.16.86.136:389 -D "CN=user1,CN=Users,DC=zjun,DC=com" -w P@ssw0rd -b 'cn=domain admins,cn=users,dc=zjun,dc=com' 
```

查询域用户的时候成功

![image-20220223205730361](https://oss.zjun.info/zjun.info/202202232057500.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

查询 `domain admins` 组没有回显

![image-20220223205846726](https://oss.zjun.info/zjun.info/202202232058782.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

## 利用 Adfind 或 PowerView 脚本查询

### 通过 [Adfind](http://www.joeware.net/freetools/tools/adfind/) 查询

```bash
# 查询域管理员组
Adfind.exe -f "memberof=CN=Domain admins,CN=Users,DC=zjun,DC=com" -dn

# 查询企业管理员组
Adfind.exe -f "memberof=CN=enterprise admins,CN=Users,DC=zjun,DC=com" -dn

# 查询域中所有机器
AdFind.exe -f "objectcategory=computer" -dn

# 查询域控
AdFind.exe -sc dclist

# 查询所有用户
Adfind.exe -b dc=zjun,dc=com -f "objectcategory=user" -dn
```

![image-20220223211228528](https://oss.zjun.info/zjun.info/202202232112634.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)

### 通过 PowerView 进行查询

```powershell
Import-Module .\PowerView.ps1

# 返回所有用户详细信息
Get-Netuser

# 获取所有域控制器
Get-NetDomainController

# 获取所有域内机器详细信息
Get-NetComputer

# 获取所有域内组和组成员信息
Get-NetGroup
```

![image-20220223211431819](https://oss.zjun.info/zjun.info/202202232114414.png?x-oss-process=image/watermark,size_20,text_emp1bnx6anVuLmluZm8=,color_AAAAAA)
