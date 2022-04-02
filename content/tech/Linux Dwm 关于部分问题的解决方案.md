---
title: "Linux Dwm 关于部分问题的解决方案"
slug: solutions-to-some-problems-with-linux-and-dwm
aliases: ["/2020/solutions-to-some-problems-with-linux-and-dwm.html"]
date: 2020-04-12 12:50:05
categories: ["Linux"]
tags: ["Linux", "Archlinux", "Dwm"]
toc: true
draft: false
---

记录 Archlinux 使用 Dwm 窗口管理器的一些重要的设置和部分解决方案，当然大部分的东西都来自[ArchWiki](https://wiki.archlinux.org/)。部分是个人经验，为了日后方便查阅，所以简单记录一下。

## 0x01 java 程序显示异常

参考：

<https://wiki.archlinux.org/index.php/Java>

<https://wiki.archlinux.org/index.php/Java_Runtime_Environment_fonts>

### java 程序启动异常

相信绝大部分使用 `linux` 的用户可能都遇到过，比如 `burpsuite` 字体发虚，特别在 `dwm` 窗口管理器中，大部分 `java` 程序，包括[JetBrains](https://www.jetbrains.com/)的所有软件都无法正常开启，在我查阅了 `archwiki` 后，终于解决了这一大问题。

在 `archlinux` 可以使用 `archlinux-java` 命令随时切换不同 `java` 版本

在 `dwm` 中，他本来就是一个窗口管理器，但 `JVM` 需要你在不同的窗口管理器中才能解决在窗口管理器发生的 `Java GUIs` 渲染问题。

所以使用 `suckless` 官方给出的[wmname](https://tools.suckless.org/x/wmname/)冒充另一个窗口管理器

```bash
wmname LG3D
```

必须在运行了这条命令后重启有问题的程序，也可以把此命令设为开机自启更加方便。

### java 程序字体渲染

启用抗锯齿显示，将以下内容添加到 `/etc/environment` 中：

```bash
_JAVA_OPTIONS='-Dawt.useSystemAAFontSettings=lcd'
```

使用 `GTK` 的显示风格，将下面的内容添加到 `~/.bashrc` 中：

```bash
_JAVA_OPTIONS='-Dswing.defaultlaf=com.sun.java.swing.plaf.gtk.GTKLookAndFeel'
```

即使通过 `Java` 选项强制执行了抗锯齿，得到的抗锯齿效果也可能不如本机应用程序。可以通过 `OpenJDK` 的一个补丁来弥补，[AUR](https://wiki.archlinux.org/index.php/AUR)提供了这个补丁：

修补后的 `OpenJDK7` 可用 [jre7-openjdk-infinality](https://aur.archlinux.org/packages/jre7-openjdk-infinality/)

修补后的 `OpenJDK8` 可用 [jre8-openjdk-infinality](https://aur.archlinux.org/packages/jre8-openjdk-infinality/)

**字体修改：**

使用 `Microsoft` 的字体。在[AUR](https://wiki.archlinux.org/index.php/AUR)安装[ttf-ms-fonts](https://aur.archlinux.org/packages/ttf-ms-fonts/)

将以下内容添加到 `/etc/environment` 以启用这些字体

```bash
JAVA_FONTS=/usr/share/fonts/TTF
```

**修复乱码 (For JRE8):**

将字体文件放在下面的目录下。如果目录不存在，则创建该目录。

```bash
/usr/lib/jvm/java-8-openjdk/jre/lib/fonts/fallback/
```

ok！做完这些步骤后，你的 `archlinux` 启动 `java` 程序应该会有一个很不错的显示效果，布局也正常了，看看我的 `burpsuite` 显示效果，很完美。

![somesolutions-1](https://oss.zjun.info/zjun.info/somesolutions-1.png)

## 0x02 导入系统证书

参考：

<https://www.archlinux.org/news/ca-certificates-update/>

这一步很重要，在 `archlinux` 中最好的证书导入方式就是把证书直接导入系统当中，不论是 `burpsuite` 或是 `xray` 或是一些 `vpn` 证书，导入系统的效果最好，三条命令完成。

```bash
sudo cp xxx.crt /etc/ssl/certs/
sudo cp xxx.crt /etc/ca-certificates/trust-source/anchors/
sudo trust extract-compat
```

## 0x03 可视化蓝牙配置

参考：

<https://wiki.archlinux.org/index.php/Bluetooth>

安装蓝牙、蓝牙音频及可视化管理工具：

```bash
yay -S bluez bluez-utils pulseaudio-bluetooth blueman
```

在 `/etc/pulse/system.pa` 增加下面内容：

```bash
load-module module-bluetooth-policy
load-module module-bluetooth-discover
```

启动蓝牙服务：

```bash
systemctl start bluetooth.service
```

启动 `blueman` 管理工具，当然你可以把它设为开机自启：

```bash
blueman-applet &
```

## 0x04 TIM 解决方案

当然 `archlinuxcn 源` 里有 `qq-linux` , 但是这个谁用谁知道，反正我不喜欢用，其次可以选择 `deepin-qq` , 可用 `archlinuxcn 源` 的 `deepin.com.qq.office` , 但是该版本较旧，推荐 `aur 源` 的 `deepin-wine-tim` , 直接下载编译，随时保持最新版， `deepin-qq` 在非 `gnome` 环境下主要存在 `3个` 问题。

**其一：**

`dwm` 每次重启后 `tim` 都无法开启，修改 `wine` 版本可解决，将 `/opt/deepinwine/apps/Deepin-TIM/run.sh` 和 `/opt/deepinwine/tools/run.sh` 的 `WINE_CMD` 一项都修改为 `wine` , 这也可以解决使用 `deepin-wine` 时的字体显示问题。

```bash
WINE_CMD="wine"
```

**其二：**

需提前运行 `gnome-settings-daemon` 依赖，但是运行后会导致 `gkt` 主题遭到破坏，运行以下 `两条` 命令重新设置主题：

```bash
gsettings set org.gnome.desktop.interface gtk-theme Adapta-Eta
gsettings set org.gnome.desktop.interface icon-theme Arc
```

当然我都是开机自启的包括运行 `gnome-settings-daemon`

```bash
nohup /usr/lib/gsd-xsettings > /dev/null 2>&1
```

**其三：**

`TIM` 无法显示图片，包括用户头像等，原因在于 `deepin-qq` 走的是 `ipv6` 的线路，解决方案是禁用本机 `ipv6` , 但我不推荐，推荐使用代理，但是 `tim` 登录显示原因 `linux` 上设置不了，所以在 `windows` 上设置后将配置文件复制过来即可

```bash
C:\Users\Administrator\Documents\Tencent Files\All Users\TIM
```

替换

```bash
~/Documents/Tencent Files/All Users/TIM
```

## 0x05 linux 网易云音乐无法输入中文

`linux` 上网易云音乐使用其自己的 `qt` 框架，无法共用系统环境配置，所以单独为其配置一下环境变量即可，修改 `/opt/netease/netease-cloud-music/netease-cloud-music.bash`

先注释三行

```bash
#export LD_LIBRARY_PATH="${HERE}"/libs
#export QT_PLUGIN_PATH="${HERE}"/plugins
#export QT_QPA_PLATFORM_PLUGIN_PATH="${HERE}"/plugins/platforms
```

再添加两行，完美解决

```bash
export LD_LIBRARY_PATH=/usr/lib
export XDG_CURRENT_DESKTOP=DDE
```
