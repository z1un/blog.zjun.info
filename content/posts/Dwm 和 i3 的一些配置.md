---
title: "Dwm 和 i3 的一些配置"
slug: some-configurations-of-dwm-and-i3
url: /2020/some-configurations-of-dwm-and-i3.html
date: 2020-01-15 12:50:05
categories: ["Linux"]
tags: ["Linux", "Archlinux", "Dwm", "i3", "窗口管理器"]
toc: true
draft: false
---

`i3` 使用了快 2 个月，现换成了我更喜欢的 `dwm` 。[i3](https://github.com/z1un/.config)和[dwm](https://github.com/z1un/dwm)都放在 `github` ，包括常用依赖，及字体等。

![i3-1](https://oss.zjun.info/zjun.info/i3-1.webp)

## 0x01 dwm

![i3-2](https://oss.zjun.info/zjun.info/i3-2.webp)

[dwm](https://dwm.suckless.org/)是使用 c 编写的一个超级轻量的窗口管理器，其源码不超过 2000 行。不同与传统窗口管理器的体验，但我更喜欢 `dwm`

我的[脚本文件](https://github.com/z1un/scripts)。

我使用的补丁：

* [dwm-alpha-20180613-b69c870.diff](https://dwm.suckless.org/patches/alpha/)
* [dwm-autostart-20161205-bb3bd6f.diff](https://dwm.suckless.org/patches/autostart/)
* [dwm-awesomebar-20191003-80e2a76.diff](https://dwm.suckless.org/patches/awesomebar/)
* [dwm-fullscreen-6.2.diff](https://dwm.suckless.org/patches/fullscreen/)
* [dwm-hide-and-restore.diff](https://github.com/theniceboy/dwm-hide-and-restore-win.diff) (by theniceboy)
* [dwm-hide_vacant_tags-6.2.diff](https://dwm.suckless.org/patches/hide_vacant_tags/)
* [dwm-noborder-6.2.diff](https://dwm.suckless.org/patches/noborder/)
* [dwm-pertag-20170513-ceac8c9.diff](https://dwm.suckless.org/patches/pertag/)
* [dwm-r1522-viewontag.diff](https://dwm.suckless.org/patches/viewontag/)
* [dwm-rotatestack-20161021-ab9571b.diff](https://dwm.suckless.org/patches/rotatestack/)
* [dwm-vanitygaps-20190508-6.2.diff](https://dwm.suckless.org/patches/vanitygaps/)

自用版本[dwm 仓库](https://github.com/z1un/dwm), 可直接 make。

## 0x02 i3

增添部分软件启动快捷键

添加了一些自启动和定时启动脚本

## 0x03 alacritty

修改字体以及大小与配色

```yml
font:
  normal:
    family: Source Code Pro
  bold:
    family: Source Code Pro
  italic:
    family: Source Code Pro
  size: 8

background_opacity: 0.9
# Colors (Snazzy)
colors:
  # Default colors
  primary:
    background: '0x282a36'
    foreground: '0xf8f8f2'

  # Normal colors
  normal:
    black:   '0x44475a'
    red:     '0xff5555'
    green:   '0x50fa7b'
    yellow:  '0xf1fa8c'
    blue:    '0xbd93f9'
    magenta: '0xff79c6'
    cyan:    '0x8be9fd'
    white:   '0xffffff'

  # Bright colors
  bright:
    black:   '0x44475a'
    red:     '0xff5555'
    green:   '0x50fa7b'
    yellow:  '0xf1fa8c'
    blue:    '0xbd93f9'
    magenta: '0xff79c6'
    cyan:    '0x8be9fd'
    white:   '0xffffff'
```

## 0x04 polybar

添加屏幕亮度，音量大小管理，网络管理，CPU 占用率与温度，电量，时间

## 0x05 vim

添加部分插件

```yml
"       _
"__   _(_)_ __ ___  _ __ ___
"\ \ / / | '_ ` _ \| '__/ __|
" \ V /| | | | | | | | | (__
"  \_/ |_|_| |_| |_|_|  \___|
"
"         --zjun--

set nocompatible
filetype on
filetype indent on
filetype plugin on
filetype plugin indent on
set mouse=a
set encoding=utf-8
let &t_ut=''

let mapleader=" "
syntax on
set number
set relativenumber
set cursorline
set wrap
set showcmd
set wildmenu
set hlsearch
exec "nohlsearch"
set incsearch
set ignorecase
set smartcase
set scrolloff=5

noremap xf :set splitbelow<CR>:split<CR>
noremap sf :set nosplitbelow<CR>:split<CR>
noremap yf :set splitright<CR>:vsplit<CR>
noremap zf :set nosplitbelow<CR>:vsplit<CR>

noremap = n
noremap - N
noremap <LEADER><CR> :nohlsearch<CR>

map s <nop>
map S :w<CR>
map Q :q<CR>
map R :source $MYVIMRC<CR>

map <LEADER>h <C-w>h
map <LEADER>j <C-w>j
map <LEADER>k <C-w>k
map <LEADER>l <C-w>l

map j :res +5<CR>
map k :res -5<CR>
map h :vertical resize-5<CR>
map l :vertical resize+5<CR>

map t :tabe<CR>
map th :-tabnext<CR>
map tl :+tabnext<CR>

call plug#begin('~/.vim/plugged')

Plug 'vim-airline/vim-airline'
Plug 'connorholyday/vim-snazzy'
Plug 'ycm-core/YouCompleteMe'
Plug 'dense-analysis/ale'
Plug 'mbbill/undotree'
Plug 'iamcco/markdown-preview.vim'
call plug#end()

color snazzy
let g:SnazzyTransparent = 1

" ===
" === ale
" ===
let b:ale_linters = ['pylint']
let b:ale_fixers = ['autopep8', 'yapf']

" ===
" === Undotree
" ===
let g:undotree_DiffAutoOpen = 0
map L :UndotreeToggle<CR>
```

## 0x06 ranger

`ranger` 是一款极好用的终端文件管理器，功能十分强大，一个普通文件管理器有的功能他都有。

![i3-3](https://oss.zjun.info/zjun.info/i3-3.webp)

## 0x07 i3lock

对于锁屏采用了[i3lock](https://github.com/meskarune/i3lock-fancy)，效果还不错，锁屏带有模糊的截图

在 i3config 下添加锁屏快捷键

```bash
bindsym $mod+Shift+s exec i3lock-fancy
```

![i3-4](https://oss.zjun.info/zjun.info/i3-4.jpg)
