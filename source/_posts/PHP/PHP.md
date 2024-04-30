---
title: Basic_PHP
categories:
- Front end
- PHP
tags:
- PHP
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
