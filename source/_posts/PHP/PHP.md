---
title: Basic_PHP
categories:
- Front end
- PHP
tags:
- PHP
date: 2024-05-06 11:04:22
---

# PHP 的补充知识点

## 1. 说明

1. 以菜鸟教程以及其评论为主要教材，文章主要进行知识点的补充。

    > https://www.runoob.com/php/php-tutorial.html

## 2. 知识点正文

### 2.1 字符串

1. 双引号内可以识别变量，单引号不行：
    ```php
    <?php
    $a = "我是傻逼";
    echo "你是谁？$a"
    ?>
    ```

2. 获取变量类型，除了 `var_dump()`，还有 `gettype()`，实际中使用 `gettype()` 多，因为 `var_dump()` 除了打印数据类型，还会将内容打印，因此其一般用于调试中。

### 2.2 数组

1. `foreach` 遍历关联数组，如果没有 `as` ，则默认获取的是 value：

    ```php
    <?php
    $age=array("Peter"=>"35","Ben"=>"37","Joe"=>"43");
     
    foreach($age as $x)
    {
        echo "value = " . $x;
        echo "<br>";
    }
    ?>
    ```

### 2.3 函数

1. 严格模式，严格规定函数的参数类型。
    ```php
    <?php
    declare(strict_types= 1);
    function plus(int $a, int $b) {
      return $a + $b;
    }
    ?>
    ```

    只要传不同的类型就会报错，不会进行类型转换

2. `global` 关键字和 `static` 关键字。
    `global` 关键字用于函数内部使用全局变量时，需要用 `global` 关键字注明函数内使用的变量是全局变量。
    `static` 修饰的局部变量不会被删除，其值会延续。（不常用）

3. 可以使用 `unset(变量)` 来删除一个变量。但是在局部作用域中，无法删除全局变量。

### 2.4 数组运算符

1. `+` 相同的键不覆盖，如果想要覆盖，采用函数 `array_merge(数组1, ...)`

### 2.5 特殊变量写法

1. 多个 `$` 的情况：
    ```php
    <?php
        $a = "test1";
    	$aa = "test2";
    	$aaa = "test3";
    ?>
    ```

    这个例子中，`$test1` 就是 `test2`，即 `$aa`；`$test2` 就是 `test3`，即 `$aaa`。

### 2.6 文件包含

1. `include_once` 和 `require_once` 表示只会引入一次。文件包含的实质就是直接将其他的 PHP 文件内容复制粘贴过来。使用 `_once` 可以避免重复定义问题。 
2. 一般引入公共函数、库时用 `_once` 。

## 3. 常用的一些危险函数

### 3.1 打印相关

#### 3.1.1 `print_r()`、`var_dump()` 和 `var_export()`

1. 这三个都是打印一个变量的内容。

2. 官方的定义：

    > **print_r()** displays information about a variable in a way that's readable by humans.
    > var_dump — Dumps information about a variable. This function displays structured information about one or more expressions that includes its type and value. Arrays and objects are explored recursively with values indented to show structure.
    > **var_export()** gets structured information about the given variable. It is similar to [var_dump()](https://www.php.net/manual/en/function.var-dump.php) with one exception: the returned representation is valid PHP code.

#### 3.1.2 `file_get_content()` 和 `highlight_file()`

1. 这两个都是用来打印文件内容的。
2. `file_get_content()` 返回的结果是 `string`，失败则返回 `false`。
3. `highlight_file()` 就是彩色返回内容。
4. `file_get_content()` 接收的变量的内容如果外部可控（例如通过 GET），这时需要借助**文件相关的伪协议以传入文件流**，例如 `file` 或者 `data` 伪协议，普通的 `str` 会报错。

### 3.2 文件和文件夹相关操作

#### 3.2.1 `scandir()`

1. 官方解释：

    > Returns an [array](https://www.php.net/manual/en/language.types.array.php) of files and directories from the `directory`.

2. 注意返回结果是 `array`，因此看后续结果就需要借助[变量打印函数。](# 3.1.1 `print_r()`、`var_dump()` 和 `var_export()`)

### 3.3 编码和特殊字符绕过函数

#### 3.3.1 `chr()`

1. 官方解释：

    > This can be used to create a one-character string in a single-byte encoding such as **ASCII, ISO-8859, or Windows 1252**

2. 一般直接输入一个字符的十进制 ASCII 就行。

3. 这个方法就可以绕过一些代码层面上的过滤。

## 4. PHP 的一些危险特征（和序列化相关的详见 PHP 的序列化部分）

### 4.1 字符串解析特征绕过 waf

1. 直接上图
    ![66.png](PHP/66.png)

2. 文章参考：

    > https://nosec.org/home/detail/2759.html

3. 以后有机会再验证图片的真实性吧。

### 4.2 PHP 中 MD5 的常见绕过

1. 别人总结的挺好，这里就直接粘贴了，个人补充一下细节：

    > https://blog.csdn.net/iczfy585/article/details/106081299

2. 有关第一点的 16 进制数，PHP 对其进行 MD5 的 16 进制加密后，生成的实际是 含 16 进制数的字符串。至于后续解析成看得懂的字符的过程，实际上是 MySQL 在操作。在字符串上下文，十六进制字符串中的每一对十六进制数字会根据十六进制的 ASCII 表，被转换成一个字符。

3. PHP 中，GET 或者 POST 所传递的变量的内容，可以是数组。也就是 PHP 的数组语法。
