---
title: "快速脚本编写场景下的 neovim 配置文件"
slug: neovim-configuration-file-in-a-fast-scripting-scenario-1
aliases: ["/2020/neovim-configuration-file-in-a-fast-scripting-scenario-1.html"]
date: 2020-08-31 12:50:05
categories: ["Linux"]
tags: ["Linux", "Neovim", "Vim", "Nvim"]
toc: true
draft: false
---

neovim 相较于 vim 更具有优势，不管从代码本身上而言还是扩展来看，neovim 更像是 vim 的新一代产品，neovim 也基本支持 vim 的所有配置。 很多师傅把 neovim 改成了一个无比完善的 IDE，功能也十分强大，但是对我而言这只是一件费时的力气活，我对 neovim 的使用场景仅限于简单且快速的脚本编写以及文件预览，在写很短的脚本的时候通常不愿意打开臃肿又缓慢的 IDE，但是原生的 neovim 拿来写代码又过于硬核，所以以我的使用习惯而有了下面简洁但不失功能的 neovim 配置文件。

主要代码仅 550 行左右。

代码仓库：<https://github.com/z1un/Config/tree/master/nvim>

## 插件

首先确保[vim-plug](https://github.com/junegunn/vim-plug)已经存在。

随后进入 neovim 运行 `:PlugInstall` ，将会自动下载插件与 coc 扩展。

插件列表如下：

```
" beautify
Plug 'theniceboy/eleline.vim'
Plug 'theniceboy/vim-deus'
Plug 'mg979/vim-xtabline'
"Plug 'connorholyday/vim-snazzy'
Plug 'mhinz/vim-startify'
Plug 'bling/vim-bufferline'
Plug 'bpietravalle/vim-bolt'
Plug 'ryanoasis/vim-devicons'
" highlight
Plug 'RRethy/vim-hexokinase', { 'do': 'make hexokinase' }
Plug 'RRethy/vim-illuminate'
" code
Plug 'Chiel92/vim-autoformat'
Plug 'neoclide/coc.nvim', {'branch': 'release'}
Plug 'yggdroot/indentline'
Plug 'wellle/tmux-complete.vim'
Plug 'honza/vim-snippets'
Plug 'luochen1990/rainbow'
" tree
Plug 'mbbill/undotree'
" Python
Plug 'Vimjas/vim-python-pep8-indent', { 'for' :['python', 'vim-plug'] }
Plug 'numirias/semshi', { 'do': ':UpdateRemotePlugins', 'for' :['python', 'vim-plug'] }
Plug 'tweekmonster/braceless.vim', { 'for' :['python', 'vim-plug'] }
" Git
Plug 'airblade/vim-gitgutter'
Plug 'theniceboy/vim-gitignore', { 'for': ['gitignore', 'vim-plug'] }
" Taglist
Plug 'liuchengxu/vista.vim'
```

coc 扩展：

```
let g:coc_global_extensions = [
    \ 'coc-actions',
    \ 'coc-css',
    \ 'coc-phpls',
    \ 'coc-diagnostic',
    \ 'coc-explorer',
    \ 'coc-flutter-tools',
    \ 'coc-gitignore',
    \ 'coc-html',
    \ 'coc-json',
    \ 'coc-lists',
    \ 'coc-prettier',
    \ 'coc-pyright',
    \ 'coc-python',
    \ 'coc-snippets',
    \ 'coc-sourcekit',
    \ 'coc-syntax',
    \ 'coc-tasks',
    \ 'coc-todolist',
    \ 'coc-translator',
    \ 'coc-tslint-plugin',
    \ 'coc-tsserver',
    \ 'coc-vimlsp',
    \ 'coc-vetur',
    \ 'coc-yaml',
    \ 'coc-yank'
]
```

## 功能

包括代码自动格式化，语法检查纠错，命令补全，支持 html、css、json、python、sh、go、swift、lua、php、yml、vimlsp 等语言代码。

支持代码修改状态管理，一键代码运行等。

除此还有 neovim 的美化。其中部分图标可能需要 <https://github.com/ryanoasis/nerd-fonts>

这会使得 neovim 看起来更酷。

## 快捷键

快捷键设置：

* 全局搜索，保存，退出

  | 行为 | 快捷键 |
  | ---- | ------ |
  | 上   | =      |
  | 下   | -      |
  | 清屏 | q      |
  | 保存 | ctrl+s |
  | 退出 | ctrl+q |

* neovim 与物理机之间的 copy

  | 行为 | 快捷键 |
  | ---- | ------ |
  | 复制 | Y      |

* Undotree

  | 行为               | 快捷键 |
  | ------------------ | ------ |
  | 显示可视化的撤销树 | ctrl+l |

* 函数与变量列表

  | 行为               | 快捷键 |
  | ------------------ | ------ |
  | 显示函数与变量列表 | V      |

* 运行代码，支持 python，java，go，php

  | 行为     | 快捷键 |
  | -------- | ------ |
  | 运行代码 | ctrl+r |

这个配置文件，我暂时没有添加 markdown 的预览支持，也不打算添加，因为 markdown 我更喜欢使用 typora，启动速度也很快。
