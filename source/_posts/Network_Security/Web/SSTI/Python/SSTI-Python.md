---
title: SSTI-Python
categories:
- Network_Security
- Web
- SSTI-Python
tags:
- Network_Security
- Web
- SSTI
---

# Python 中的 SSTI

## 1. Jinja2

### 1.1 Flask 基础

1. 一些常见的入门网站：

    > https://read.helloflask.com/hello/

2. 常见的 Flask 项目开头代码：

    ```python
    import flask
    app = flask.Flask(__name__)
    @app.route('/')
    def hello():
        return 'Welcome to My Watchlist!'
    ```

3. app，就是：

    > 所有的 Flask 都必须创建程序实例，web 服务器使用 wsgi 协议，把客户端所有的请求都转发给这个程序实例。程序实例是 Flask 的对象，一般情况下用 `app = flask.Flask(__name__)` 实例化。
    > Flask 类只有一个必须指定的参数，即程序主模块或者包的名字，`__name__` 是系统变量，该变量指的是本 py 文件的文件名。
    
4. 然后就是具体路由，路由的方式有很多，可以详见官方文档：

    > https://flask.github.net.cn/quickstart.html#id7

### 1.2 Jinja2 的内容

1. 关键的渲染方法就是 `flask.render_template_string(str)` 和 `flask.render_template(fileName)`。

2. 目前 Jinja2 相关教程中，个人认为写的比较好的就是：

    > https://blog.csdn.net/qq_38154820/article/details/111399386

3. 着重提及一下，**常见的魔术方法要留意**，因为 SSTI 中用的比较多。

4. 大部分给的教程都是通过魔术方法从 `Object` 开始，一层一层找到**命令执行相关**的函数，然后注册函数并执行。

5. 对于某些 CTF 题，可能 Flag 是在当前系统或者环境变量里面，例如 ：
    ```python
    app = flask.Flask(__name__)
    app.config['FLAG'] = os.environ.pop('FLAG')
    ```

    这个时候，就要考虑读取系统的变量。
    常用的魔术方法就是 `__globals__` 来获取函数所在模块命名空间中的**所有变量**。Flask 中的能显示全局变量的有：`url_for()` 和 `get_flashed_messages` 等。（TODO 不懂是怎么发现的）。
    参考链接：
    
    > https://blog.csdn.net/qq_45290991/article/details/120117615
    
6. Python 中可以使用 `魔术方法名['魔术方法名']` 来代替 `魔术方法名.魔术方法名`。即可以使用：`__init__['globals']` 代替 `__init__.__globals__`。这样某些关键字可以通过字符串拼接来过滤。
