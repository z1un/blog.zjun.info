---
title: "CISCN 2020 线上初赛部分 WriteUp"
slug: ciscn-2020-preliminaries
aliases: ["/2020/ciscn-2020-preliminaries.html"]
date: 2020-08-21 12:50:05
categories: ["CTF"]
tags: ["CTF", "CISCN 2020", "WriteUp"]
toc: true
draft: false
---

这次比赛分为在线知识问答和 ctf，这里是我们 IRISES 队伍的 ctf writeup。可惜的是队内没有 pwn 手，而且 web 方向的题也没有偏向实战类型，导致 pwn 直接没看，挺尴尬的一场比赛。

## Web

### 0x01 easyphp

题目：

```php
<?php
    //题目环境：php:7.4.8-apache
    $pid = pcntl_fork();
    if ($pid == -1) {
        die('could not fork');
    }else if ($pid){
        $r=pcntl_wait($status);
        if(!pcntl_wifexited($status)){
            phpinfo();
        }
    }else{
        highlight_file(__FILE__);
        if(isset($_GET['a'])&&is_string($_GET['a'])&&!preg_match("/[:\\\\]|exec|pcntl/i",$_GET['a'])){
            call_user_func_array($_GET['a'],[$_GET['b'],false,true]);
        }
        posix_kill(posix_getpid(), SIGUSR1);
    }
```

回调一个存在的函数，然后让进程退出即可拿到 phpinfo()。

Payload:

 `?a=call_user_func&&b=pcntl_wait`

### 0x02 easytrick

题目：

```php
<?php
class trick{
    public $trick1;
    public $trick2;
    public function __destruct(){
        $this->trick1 = (string)$this->trick1;
        if(strlen($this->trick1) > 5 || strlen($this->trick2) > 5){
            die("你太长了");
        }
        if($this->trick1 !== $this->trick2 && md5($this->trick1) === md5($this->trick2) && $this->trick1 != $this->trick2){
            echo file_get_contents("/flag");
        }
    }
}
highlight_file(__FILE__);
unserialize($_GET['trick']);
```

Payload:

```php
<?php

class trick
{
    public $trick1;
    public $trick2;

    public function __destruct()
    {
        $this->trick1 = (string)$this->trick1;
        if (strlen($this->trick1) > 5 || strlen($this->trick2) > 5) {
            die("你太长了");
        }
        if ($this->trick1 !== $this->trick2 && md5($this->trick1) === md5($this->trick2) && $this->trick1 != $this->trick2) {
            echo file_get_contents("/flag");
        }
    }
}

$obj = new trick();
$obj->trick1 = 1/0;
$obj->trick2 = INF;
echo serialize($obj) . "\n";

// O:5:"trick":2:{s:6:"trick1";d:INF;s:6:"trick2";d:INF;}
```

`string 1/0` 会直接转化为 `INF` ，可绕过长度与第二个 if 判断限制。

## Misc

### 0x01 签到

点进去后记录 IP，每个省份记录 10 个 IP 以上即可出现 flag。

### 0x02 the_best_ctf_game

解压后出现一个 flag 的文件，对其进行 hex 分析。

![ciscn2020-1](https://oss.zjun.info/zjun.info/ciscn2020-1.png)

仔细观察即可发现其中夹杂着 flag 字样，手动去除多余字符即可。

### 0x03 电脑被黑

通过 R-Studio 扫描此镜像文件发现是 Linux 系统，且扫描出部分丢失文件

![ciscn2020-2](https://oss.zjun.info/zjun.info/ciscn2020-2.png)

![ciscn2020-3](https://oss.zjun.info/zjun.info/ciscn2020-3.png)

这时需要判断扫描出来的部分文件中是否存在需要的 flag 文件，判断方法：

* 直接把文件恢复到桌面进行判断

* 用 winhex 软件对比恢复出来的部分文件是否正确，此时还可借助 winhex 软件寻找其他没有被 r-studio 软件扫面出来的文件

用 winhex 软件打开 disk_dump 文件，再在菜单栏选择专业工具，在专业工具里面点击将镜像文件转换成磁盘，这是你便能看见这个 linux 系统的结构（坏磁盘不能）

![ciscn2020-4](https://oss.zjun.info/zjun.info/ciscn2020-4.png)

在浏览窗口中可以看一下文件夹里面有哪些文件可以直接提出来，比如图中的 png 图片和 txt 文件等

![ciscn2020-5](https://oss.zjun.info/zjun.info/ciscn2020-5.png)

因为文件在 linux 系统中被删除 i 节点表是没有直接指针的，所以通过浏览窗口和全系统的文件查看和 r-studio 的对比、结合勘察后，最终确定在 r-studio 的 flag.txt 文件就是我们要找的 flag 文件

![ciscn2020-6](https://oss.zjun.info/zjun.info/ciscn2020-6.png)

winhex 相对应的位置是 17472 扇区，先提取出来：

![ciscn2020-7](https://oss.zjun.info/zjun.info/ciscn2020-7.png)

binwalk 再分析磁盘，提取出一个 elf 可执行文件，ida 分析之：

![ciscn2020-8](https://oss.zjun.info/zjun.info/ciscn2020-8.png)

根据代码得出算法：

```python
f = open("flag.txt", "rb")
a = f.read()
f.close()

v5 = 0
for p, v6 in enumerate(a):
   print(chr((v6 ^ (0x22 * (p + 1))) - v5 & 0xFF), end="")
   v5 = (v5 + 2) & 0xF

if __name__ == '__main__':
   pass
```

## Revere

### 0x01 z3

z3 库一把梭，payload：

```python
import z3
import struct

v46 = z3.Int("v46")
v47 = z3.Int("v47")
v48 = z3.Int("v48")
v49 = z3.Int("v49")
v50 = z3.Int("v50")
v51 = z3.Int("v51")
v52 = z3.Int("v52")
v53 = z3.Int("v53")
v54 = z3.Int("v54")
v55 = z3.Int("v55")
v56 = z3.Int("v56")
v57 = z3.Int("v57")
v58 = z3.Int("v58")
v59 = z3.Int("v59")
v60 = z3.Int("v60")
v61 = z3.Int("v61")
v62 = z3.Int("v62")
v63 = z3.Int("v63")
v64 = z3.Int("v64")
v65 = z3.Int("v65")
v66 = z3.Int("v66")
v67 = z3.Int("v67")
v68 = z3.Int("v68")
v69 = z3.Int("v69")
v70 = z3.Int("v70")
v71 = z3.Int("v71")
v72 = z3.Int("v72")
v73 = z3.Int("v73")
v74 = z3.Int("v74")
v75 = z3.Int("v75")
v76 = z3.Int("v76")
v77 = z3.Int("v77")
v78 = z3.Int("v78")
v79 = z3.Int("v79")
v80 = z3.Int("v80")
v81 = z3.Int("v81")
v82 = z3.Int("v82")
v83 = z3.Int("v83")
v84 = z3.Int("v84")
v85 = z3.Int("v85")
v86 = z3.Int("v86")
v87 = z3.Int("v87")

data = bytearray([
    0x17, 0x4F, 0x00, 0x00, 0xF6, 0x9C, 0x00, 0x00, 0xDB, 0x8D,
    0x00, 0x00, 0xA6, 0x8E, 0x00, 0x00, 0x29, 0x69, 0x00, 0x00,
    0x11, 0x99, 0x00, 0x00, 0xA2, 0x40, 0x00, 0x00, 0x3E, 0x2F,
    0x00, 0x00, 0xB6, 0x62, 0x00, 0x00, 0x82, 0x4B, 0x00, 0x00,
    0x6C, 0x48, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0xD7, 0x52,
    0x00, 0x00, 0xEF, 0x2D, 0x00, 0x00, 0xDC, 0x28, 0x00, 0x00,
    0x0D, 0x64, 0x00, 0x00, 0x8F, 0x52, 0x00, 0x00, 0x3B, 0x61,
    0x00, 0x00, 0x81, 0x47, 0x00, 0x00, 0x17, 0x6B, 0x00, 0x00,
    0x37, 0x32, 0x00, 0x00, 0x93, 0x2A, 0x00, 0x00, 0x5F, 0x61,
    0x00, 0x00, 0xBE, 0x50, 0x00, 0x00, 0x8E, 0x59, 0x00, 0x00,
    0x56, 0x46, 0x00, 0x00, 0x31, 0x5B, 0x00, 0x00, 0x3A, 0x31,
    0x00, 0x00, 0x10, 0x30, 0x00, 0x00, 0xFE, 0x67, 0x00, 0x00,
    0x5F, 0x4D, 0x00, 0x00, 0xDB, 0x58, 0x00, 0x00, 0x99, 0x37,
    0x00, 0x00, 0xA0, 0x60, 0x00, 0x00, 0x50, 0x27, 0x00, 0x00,
    0x59, 0x37, 0x00, 0x00, 0x53, 0x89, 0x00, 0x00, 0x22, 0x71,
    0x00, 0x00, 0xF9, 0x81, 0x00, 0x00, 0x24, 0x55, 0x00, 0x00,
    0x71, 0x89, 0x00, 0x00, 0x1D, 0x3A, 0x00, 0x00
])
offset = 0
s = z3.Solver()
s.add(34 * v49 + 12 * v46 + 53 * v47 + 6 * v48 + 58 * v50 + 36 * v51 + v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(27 * v50 + 73 * v49 + 12 * v48 + 83 * v46 + 85 * v47 + 96 * v51 + 52 * v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(24 * v48 + 78 * v46 + 53 * v47 + 36 * v49 + 86 * v50 + 25 * v51 + 46 * v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(78 * v47 + 39 * v46 + 52 * v48 + 9 * v49 + 62 * v50 + 37 * v51 + 84 * v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(48 * v50 + 14 * v48 + 23 * v46 + 6 * v47 + 74 * v49 + 12 * v51 + 83 * v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(15 * v51 + 48 * v50 + 92 * v48 + 85 * v47 + 27 * v46 + 42 * v49 + 72 * v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(26 * v51 + 67 * v49 + 6 * v47 + 4 * v46 + 3 * v48 + 68 * v52 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(34 * v56 + 12 * v53 + 53 * v54 + 6 * v55 + 58 * v57 + 36 * v58 + v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(27 * v57 + 73 * v56 + 12 * v55 + 83 * v53 + 85 * v54 + 96 * v58 + 52 * v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(24 * v55 + 78 * v53 + 53 * v54 + 36 * v56 + 86 * v57 + 25 * v58 + 46 * v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(78 * v54 + 39 * v53 + 52 * v55 + 9 * v56 + 62 * v57 + 37 * v58 + 84 * v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(48 * v57 + 14 * v55 + 23 * v53 + 6 * v54 + 74 * v56 + 12 * v58 + 83 * v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(15 * v58 + 48 * v57 + 92 * v55 + 85 * v54 + 27 * v53 + 42 * v56 + 72 * v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(26 * v58 + 67 * v56 + 6 * v54 + 4 * v53 + 3 * v55 + 68 * v59 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(34 * v63 + 12 * v60 + 53 * v61 + 6 * v62 + 58 * v64 + 36 * v65 + v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(27 * v64 + 73 * v63 + 12 * v62 + 83 * v60 + 85 * v61 + 96 * v65 + 52 * v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(24 * v62 + 78 * v60 + 53 * v61 + 36 * v63 + 86 * v64 + 25 * v65 + 46 * v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(78 * v61 + 39 * v60 + 52 * v62 + 9 * v63 + 62 * v64 + 37 * v65 + 84 * v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(48 * v64 + 14 * v62 + 23 * v60 + 6 * v61 + 74 * v63 + 12 * v65 + 83 * v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(15 * v65 + 48 * v64 + 92 * v62 + 85 * v61 + 27 * v60 + 42 * v63 + 72 * v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(26 * v65 + 67 * v63 + 6 * v61 + 4 * v60 + 3 * v62 + 68 * v66 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(34 * v70 + 12 * v67 + 53 * v68 + 6 * v69 + 58 * v71 + 36 * v72 + v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(27 * v71 + 73 * v70 + 12 * v69 + 83 * v67 + 85 * v68 + 96 * v72 + 52 * v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(24 * v69 + 78 * v67 + 53 * v68 + 36 * v70 + 86 * v71 + 25 * v72 + 46 * v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(78 * v68 + 39 * v67 + 52 * v69 + 9 * v70 + 62 * v71 + 37 * v72 + 84 * v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(48 * v71 + 14 * v69 + 23 * v67 + 6 * v68 + 74 * v70 + 12 * v72 + 83 * v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(15 * v72 + 48 * v71 + 92 * v69 + 85 * v68 + 27 * v67 + 42 * v70 + 72 * v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(26 * v72 + 67 * v70 + 6 * v68 + 4 * v67 + 3 * v69 + 68 * v73 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(34 * v77 + 12 * v74 + 53 * v75 + 6 * v76 + 58 * v78 + 36 * v79 + v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(27 * v78 + 73 * v77 + 12 * v76 + 83 * v74 + 85 * v75 + 96 * v79 + 52 * v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(24 * v76 + 78 * v74 + 53 * v75 + 36 * v77 + 86 * v78 + 25 * v79 + 46 * v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(78 * v75 + 39 * v74 + 52 * v76 + 9 * v77 + 62 * v78 + 37 * v79 + 84 * v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(48 * v78 + 14 * v76 + 23 * v74 + 6 * v75 + 74 * v77 + 12 * v79 + 83 * v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(15 * v79 + 48 * v78 + 92 * v76 + 85 * v75 + 27 * v74 + 42 * v77 + 72 * v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(26 * v79 + 67 * v77 + 6 * v75 + 4 * v74 + 3 * v76 + 68 * v80 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(34 * v84 + 12 * v81 + 53 * v82 + 6 * v83 + 58 * v85 + 36 * v86 + v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(27 * v85 + 73 * v84 + 12 * v83 + 83 * v81 + 85 * v82 + 96 * v86 + 52 * v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(24 * v83 + 78 * v81 + 53 * v82 + 36 * v84 + 86 * v85 + 25 * v86 + 46 * v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(78 * v82 + 39 * v81 + 52 * v83 + 9 * v84 + 62 * v85 + 37 * v86 + 84 * v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(48 * v85 + 14 * v83 + 23 * v81 + 6 * v82 + 74 * v84 + 12 * v86 + 83 * v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(15 * v86 + 48 * v85 + 92 * v83 + 85 * v82 + 27 * v81 + 42 * v84 + 72 * v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4
s.add(26 * v86 + 67 * v84 + 6 * v82 + 4 * v81 + 3 * v83 + 68 * v87 == struct.unpack_from("<I", data, offset)[0])
offset += 4

s.check()
m = s.model()
print(chr(int(str(m[v46]))), end="")
print(chr(int(str(m[v47]))), end="")
print(chr(int(str(m[v48]))), end="")
print(chr(int(str(m[v49]))), end="")
print(chr(int(str(m[v50]))), end="")
print(chr(int(str(m[v51]))), end="")
print(chr(int(str(m[v52]))), end="")
print(chr(int(str(m[v53]))), end="")
print(chr(int(str(m[v54]))), end="")
print(chr(int(str(m[v55]))), end="")
print(chr(int(str(m[v56]))), end="")
print(chr(int(str(m[v57]))), end="")
print(chr(int(str(m[v58]))), end="")
print(chr(int(str(m[v59]))), end="")
print(chr(int(str(m[v60]))), end="")
print(chr(int(str(m[v61]))), end="")
print(chr(int(str(m[v62]))), end="")
print(chr(int(str(m[v63]))), end="")
print(chr(int(str(m[v64]))), end="")
print(chr(int(str(m[v65]))), end="")
print(chr(int(str(m[v66]))), end="")
print(chr(int(str(m[v67]))), end="")
print(chr(int(str(m[v68]))), end="")
print(chr(int(str(m[v69]))), end="")
print(chr(int(str(m[v70]))), end="")
print(chr(int(str(m[v71]))), end="")
print(chr(int(str(m[v72]))), end="")
print(chr(int(str(m[v73]))), end="")
print(chr(int(str(m[v74]))), end="")
print(chr(int(str(m[v75]))), end="")
print(chr(int(str(m[v76]))), end="")
print(chr(int(str(m[v77]))), end="")
print(chr(int(str(m[v78]))), end="")
print(chr(int(str(m[v79]))), end="")
print(chr(int(str(m[v80]))), end="")
print(chr(int(str(m[v81]))), end="")
print(chr(int(str(m[v82]))), end="")
print(chr(int(str(m[v83]))), end="")
print(chr(int(str(m[v84]))), end="")
print(chr(int(str(m[v85]))), end="")
print(chr(int(str(m[v86]))), end="")
print(chr(int(str(m[v87]))), end="")

if __name__ == '__main__':
    pass
```

### 0x02 hyperthreading

去掉花指令后 f5：

![ciscn2020-9](https://oss.zjun.info/zjun.info/ciscn2020-9.png)

`sub_401200` 和 `sub_401240` 为反调试线程

![ciscn2020-10](https://oss.zjun.info/zjun.info/ciscn2020-10.png)

根据 StartAddress 得出解密算法

```python
flag = [
    0xDD, 0x5B, 0x9E, 0x1D, 0x20, 0x9E, 0x90, 0x91, 0x90, 0x90,
    0x91, 0x92, 0xDE, 0x8B, 0x11, 0xD1, 0x1E, 0x9E, 0x8B, 0x51,
    0x11, 0x50, 0x51, 0x8B, 0x9E, 0x5D, 0x5D, 0x11, 0x8B, 0x90,
    0x12, 0x91, 0x50, 0x12, 0xD2, 0x91, 0x92, 0x1E, 0x9E, 0x90,
    0xD2, 0x9F
]

for i in flag:
    temp = ((i - 0x23) & 0xFF) ^ 0x23
    print(chr(((temp >> 6) | (temp << 2)) & 0xFF), end="")

if __name__ == '__main__':
    pass
```

## Crypto

### 0x01 bd

题目：

```python
from secret import flag
from Crypto.Util.number import *

m = bytes_to_long(flag)

p = getPrime(512)
q = getPrime(512)
N = p * q
phi = (p-1) * (q-1)
while True:
    d = getRandomNBitInteger(200)
    if GCD(d, phi) == 1:
        e = inverse(d, phi)
        break

c = pow(m, e, N)

print(c, e, N, sep='\n')

# 37625098109081701774571613785279343908814425141123915351527903477451570893536663171806089364574293449414561630485312247061686191366669404389142347972565020570877175992098033759403318443705791866939363061966538210758611679849037990315161035649389943256526167843576617469134413191950908582922902210791377220066
# 46867417013414476511855705167486515292101865210840925173161828985833867821644239088991107524584028941183216735115986313719966458608881689802377181633111389920813814350964315420422257050287517851213109465823444767895817372377616723406116946259672358254060231210263961445286931270444042869857616609048537240249
# 86966590627372918010571457840724456774194080910694231109811773050866217415975647358784246153710824794652840306389428729923771431340699346354646708396564203957270393882105042714920060055401541794748437242707186192941546185666953574082803056612193004258064074902605834799171191314001030749992715155125694272289
```

已知 c、e、N，利用 3summer 师傅的开源工具[CTF-RSA-tool](https://github.com/3summer/CTF-RSA-tool)，可直接解出 flag。

![ciscn2020-11](https://oss.zjun.info/zjun.info/ciscn2020-11.png)
