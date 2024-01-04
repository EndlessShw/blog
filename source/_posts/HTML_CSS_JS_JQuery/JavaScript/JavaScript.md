---
title: JavaScript
categories:
- Front end
- HTML_CSS_JS_JQuery
tags:
- Front end
---
# JavaScript

## 1.  初识 JavaScript

1. JavaScript 是一种运行在==客户端==的==脚本语言==
2. 脚本语言：不需要编译，运行的过程中由 JS 解释器（JS 引擎）逐行来进行解释并执行
3. 现在也可以基于 Node.js 技术进行服务器端编程
4. 作用
    - 表单动态校验（密码强度检测）（==JS最初的目的==，以减轻服务器的压力）
    - 网页特效
    - 服务端开发（Node.js）
    - 桌面程序（Electron）
    - App（Cordova）
    - 控制硬件-物联网（Ruff）
    - 游戏开发（cocos2d-JS）

---

## 2. 浏览器执行 JS 过程

1. 浏览器分成两部分：渲染引擎和 JS 引擎
    - 渲染引擎：用来解析 HTML 和 CSS，俗称内核，比如 chrome 浏览器的 blink，老版本的 webkit
    - JS 引擎：也成为 JS 解释器，用来读取网页中的 JavaScript 代码，对其处理后运行，比如 chrome 浏览器的 V8
    - 浏览器本身并不会执行 JS 代码，而是通过==内置 JavaScript 引擎（解释器）来执行 JS 代码。JS 引擎执行代码时逐行解释每一句源码（转换成机器语言），然后有计算机去执行==，所以 JavaScript 语言归为脚本语言，会逐行解释执行

---

## 3. JavaScript 的组成

1. JavaScript 组成
    - JavaScript 语法：ECMAScript
    - 页面文档对象模型：DOM
    - 浏览器对象模型：BOM
2. ECMAScript 是由 ECMA 国际（原欧洲计算机制造商协会）进行标准化的一门编程语言，这种语言在万维网上应用广泛，它往往被称为 JavaScript 或 JScript，但实际上后两者是 ECMAScript 语言的实现和扩展。==ECMAScript 规定了 JS 的编程语法和基础核心知识，是所有浏览器厂商共同遵守的一套 JS 语法工业标准==
3. DOM(Document Object Model) 文档对象模型，是 W3C 组织推荐的处理可拓展标记语言的==标准编程接口==。通过 DOM 提供的接口可以对页面上的各种元素进行操作（大小、位置、颜色等）
4. BOM(Browser Object Model) 是指浏览器对象模型，它提供了独立于内容的、可以与浏览器窗口进行互动的==对象结构==。通过 BOM 可以操作浏览器窗口，比如弹出框、控制浏览器跳转、获取分辨率等。

---

## 4. JavaScript 的书写位置

JS 有三种书写位置，分别为行内、内嵌和外部

### 1. 行内式的 JS

1. 写在 `<body></body>` 内，或者写在标签元素元素的内部，比如：

    - ```html
        <input type="button" value="alert(1)" onclick="alert(1)" />
        ```

2. 可以将单行或者少量 JS 代码写在 HTML 标签的事件属性中（以 on 开头的属性），如onclick

3. 注意单双引号：在 ==HTML 中推荐使用双引号==，==JS 中推荐使用单引号==

4. 可读性差，在 HTML 编写 JS 大量代码时，不方便阅读

5. 引号易错，引号多层嵌套匹配时，非常容易弄混

6. 特殊情况下使用



### 1. 内嵌式的 JS

1. 写在 \<head\>\</head\> 内

    - ```html
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Document</title>
            <!-- 内嵌式 JS，写在 <head> 里面 -->
            <script>
                alert(111)
            </script>
        </head>
        ```

2. 可以将多行 JS 代码写道 `<script>` 标签中

3. 内嵌 JS 是学习时常用的方式



### 3. 外部 JS 文件

1. 实例：

    - ```html
        <script src="xxx.js"></script>
        ```

2. 利于 HTML 页面代码结构化，把大段 JS 代码独立到 HTML 页面之外，既美观，也方便文件级别的复用

3. 引用外部 JS 文件 `<script>` 标签中间不可以写代码

4. 适合于 JS 代码量比较大的情况

---



## 5. JavaScript 的注释

### 1. 单行注释

1. //



### 2. 多行注释

1. /* ... */
2. 快捷键：shift + alt + a
3. 也可以修改 vscode 中多行注释的快捷键，例如为：ctrl + shift + /

---



## 6. JavaScript 常用的输入输出语句

### 1. 常见的输入输出语句

1. | 方法             | 说明                           | 归属   |
    | ---------------- | ------------------------------ | ------ |
    | alert(msg)       | 浏览器弹出警示框               | 浏览器 |
    | console.log(msg) | 浏览器控制台打印输出信息       | 浏览器 |
    | prompt(info)     | 浏览器弹出输入框，用户可以输入 | 浏览器 |

    - `console.log()` 在 F12 中查看

---



## 7. 变量

### 1. 声明

1. ```javascript
    var age;
    ```

    - 使用 `var` 关键字声明变量后，计算机会自动为变量分配内存空间
    - 在 JS 中，变量==不声明直接赋值使用==是可以的

---



## 8. JavaScript 的数据类型（简单）

### 1. 数据的具体类型

1. JavaScript 是一种==弱类型或者说是动态语言==。其不用提前声明变量的类型，在程序运行的过程中，类型会被自动确定。

2. 如上所示，由于变量具有动态类型，所以相同的变量可以用作不同的类型，即类型随时可变

    - ```javascript
        var x = 10;
        // x 从 int 变成了 字符串型
        x = 'string'
        ```

#### 1. 简单的数据类型

1. | 简单数据类型 | 说明                                                      | 默认值    |
    | ------------ | --------------------------------------------------------- | --------- |
    | Number       | 数字型，包括 int、float 和 double。                       | 0         |
    | Boolean      |                                                           | false     |
    | String       |                                                           | ""        |
    | Undefined    | `var a;` 声明了变量 a 但是没有赋值，此时 a 就是 undefined | undefined |
    | Null         | `var a = null;` 声明了变量 a 为空值                       | null      |

##### 1. 数字型

1. 对于数字型来说，0 开头的数字代表为无符号八进制数，0x 开头的数字代表十六进制
2. 最大值：`Number.MAX_VALUE` 
3. 最小值：`Number.MIN_VALUE`
4. 数字型的三个特殊值：
    - `Infinity 或者是 Number.MAX_VALUE * 2` 代表无穷大，大于任何值
    - `-Infinity 或者是 Number.MIN_VALUE * 2` 代表无穷小，小于任何值
    - `NaN` Not a Number，代表一个非数值
5. `isNaN()` 用来判断是否是非数字



##### 2. 字符串型

1. JS 可以用单引号嵌套双引号，反之亦可，总之尽量要==外双内单或者外单内双==

2. | 转义符 | 解释说明             |
    | ------ | -------------------- |
    | \n     | 换行，n 表示 newline |
    | \t     | tab 表示缩进         |
    | \b     | 空格，b 表示 blank   |

3. 获取字符串的长度：

    - `"字符串".length`

4. 字符串的拼接：+

    - 字符型与其他类型拼接，其他类型将==自动转换==成字符串型（null + ".." = "null.."，其他类型同理），注意与其他语言语言区别



#### 2. 获取变量的数据类型

1. `typeof 变量`，返回数据类型
    - `null` 返回的类型为 `object`
    - `prompt()` 函数返回的类型为字符串型



#### 3. 数据类型的转换

##### 1. 转换成字符串类型

1. | 方式              | 说明                         |
    | ----------------- | ---------------------------- |
    | ==toString()==    | 转成字符串                   |
    | String() 强制转换 | 转成字符串                   |
    | 加号拼接字符串    | 和字符串拼接的结果都是字符串 |



##### 2. 转换成数字型

1. | 方式                   | 说明                                                         |
    | ---------------------- | ------------------------------------------------------------ |
    | ==parseInt(string)==   | 将 string 类型转成 int 类型，从第一个字符（同时也是数字）开始，取连续的数字，如果开头不是数字，则返回 NaN |
    | ==parseFloat(string)== | 将 string 类型转成 float 类型                                |
    | Number() 强制转换函数  | 将 string 类型转换为==数值==型，如果待转换的变量不是包含纯数字的字符串，则返回 NaN |
    | js 隐式转换（- * / )   | 利用算术运算隐式转换为数值型                                 |



##### 3. 转换成布尔型

1. | 方式      | 说明               |
    | --------- | ------------------ |
    | Boolean() | 其他类型转成布尔值 |

    - 代表==空、否定==的值都会被转换成 false：
        - ""、0、NaN、null、undefined
    - 其余的值都会转换成 true

---



## 9. 运算符

### 1. 算术运算符

1. 浮点运算时，由于精度问题，从而得出并非想要的结果：

    1. ```javascript
        console.log(0.1 + 0.2); // 0.30000....结尾有个4
        ```

    2. 同样的，浮点数也不能直接拿来比较

    

### 2. 递增和递减运算符

1.  JavaScript 中有 `++` 和 `--`



### 3. 比较运算符

1. `===` 和 `!==` 要求值和数据类型都要比较



### 4. 逻辑运算符

1. `&&` 和 `||` 都有短路运算（逻辑中断）



---

## 10. 流程控制

### 1. if分支

1. 没啥可说的，和 Java 一样



### 2. 三元表达式

1. 语法结构：
    - `条件表达式1 ? 表达式1 : 表达式2
    - 为真返回表达式1的值，否则为表达式2的值



### 3. switch 语句

1. 同 java
2. case 相比的条件是`===`，即全等于

---



##  11. 循环

pass

---



## 12. 数组

1. 数组的创建方式：

    - ```javascript
        var arr = new Array();
        var arr = [];
        ```

2. 一个数组内可以存放多种==不同的类型==元素

3. 数组的访问同其他语言

4. 数组新增元素：

    1. 直接修改长度，给 `length` 属性直接赋值
    2. 直接对某个下标进行赋值，==可以跨越赋值，中间没有赋值的用  `undefined` 的填充==

---



## 13. 函数

### 1. 定义符

1. `function` 开头，类似于 python 中的 `def` 



### 2. 返回值

1. 和 java 一样，返回一个值。
    - 由于函数定义时不用指定返回类型，所以返回没有报错
2. 如果没有 `return` ，则默认返回 `undefined` 



### 3. arguments

1. `arguments` 是函数的一个==内置对象==，该对象中==存储了传递的所有实参==
2. `arguments` 展示形式是一个伪数组，因此可以遍历，==但是其不是真正的数组==，其类型为 `object`。其具有一下特点：
    1. 具有 `length` 属性
    2. 按索引方式存储数据
    3. 不具有数组的一些方法，比如 `push()` 和 `pop()` 方法



### 4. 函数声明

1. 第一种就是使用 `function` 来定义

2. 使用函数表达式（匿名函数）：

    1. ```javascript
        var fun = function(){...};
        fun();
        ```

---



## 14. 作用域

#### 1. 概念

1. 一段程序代码中所用到的名字并不总是有效和可用的，而限定这个名字的==可用性的代码范围==就是这个名字的==作用域==。
2. 其目的在于提高程序的可靠性，同时减少命名冲突



### 2. 作用域的范围

1. es6 之前：
    - 全局作用域：整个 `<script>` 标签，或者是一个单独的 js 文件
    - 局部作用域：在函数内部
2. 变量的作用域：
    - 全局变量：在全局作用域中的变量，以及一个特殊情况：
        - 在函数内部没有声明，但是直接赋值的变量是全局变量
    - 局部变量：在局部作用域中的变量



### 3. 执行效率

1. 全局变量只有浏览器关闭的时候才会销毁，比较占内存资源
2. 当函数执行结束时自动销毁，比较节约



### 4. JS 没有块级作用域（ES6 之前），在 ES6 时增加了

1. 在其他语言中，例如 Java 的 `if` 语句：

    - ```java
        if(){
            ...
        }
        ```

    - `if` 之外的代码不能使用内部定义的变量，该作用域即块作用域



### 5. 作用域链

1. 如果函数中还嵌套函数，那么作用域里面又会新增作用域

2. 根据在内部函数可以访问外部函数变量的这种机制，用==链式查找==决定哪些数据能被内部函数访问，就成为作用域链

3. 例如：

    - ```javascript
        var num = 1;
        function f1(){
            var num = 2;
            function f2(){
                console.log(num);
            }
            f2();
        }
        ```

    - 结果为 2，从内到外，形成一个链子，从内开始，就近原则。这里 `num = 1` 就是1级链，`num = 2` 就是2级链。从2级链找，没有找到就向上找，直到找到为止。



## 15. 预解析

### 1. 预解析

1. 例子：

    - ```javascript
        console.log(num);
        var num = 10;
        // 输出的结果不是报错，而是 undefined 类
        ```

    - ```javascript
        fun();
        var fun = function(){
            console.log(22);
        }
        // 报错，和单独定义一个函数不同
        ```

2. JavaScript 解析器在运行 JavaScript 代码的时候分为两步：预解析和代码执行：

    - JavaScript 引擎会把 JS 中==所有的 `var` 还有 `function` 提升到当前作用域的最前面==。
    - 代码执行就是按照书写代码的顺序从上往下执行

3. 预解析同时也分为==变量预解析（变量提升）==和==函数预解析（函数提升）==

    - 就是把所有的变量声明提升到当前作用域最前面，==但是不提升赋值操作==
    - 同样的，函数提升就是把所有的函数声明提到当前作用域的最前面，==但是不调用函数==

4. 案例1：

    - ```javascript
        var num = 10;
        fun();
        function fun(){
            console.log(num);
            var num = 20;
        }
        // 输出的结果为 undefined
        ```

        预解析后的结果如下：

    - ```javascript
        var num;
        function fun(){
            var num;
            console.log(num);
            num = 10;
        }
        fun();
        ```

    - ==Java 中不能函数中定义函数，c ++ 中需要定义结构体或类，再在其中定义成员变量，Python 和 JavaScript 里面可以嵌套定义==

    - 在 Java 中，似乎没有这种预解析

---



## 16. 对象

### 1. 对象的创建

1. ```javascript
    // 创建一个空对象
    var obj = {}; 
    // 或者
    var obj = new Object();
    ```

2. ```javascript
    // 属性和方法的创建是以键值对的形式表示
    var obj = {
        name: 'cjy',
        age: 20,
        ...
        // 方法
        sayHello: function(){
            console.log('hello');
            ...
        }
    }
        
    // 或者
    // 属性和方法的创建以赋值的形式表示
    var obj = new Object();
    obj.name = 'cjy';
    obj.age = 18;
    obj.sex = '男';
    ...
    obj.sayHello = function(){
        console.log('hello');
        ...
    }
    ```



### 2. 使用对象的方法和属性

1. ==对象名.属性名 或者 对象名['属性名']==

2. 对象名.方法名()



### 3. 一次性创建多个对象

1. 利用类似函数的方法创建对象，把这个函数成为构造函数（类似 Java中的类

2. ```javascript
    // 构造函数名一般是大驼峰命名法
    // 构造函数不需要 return，就可以返回结果，因为其会自动返回
    function 构造函数名字(形参1, 形参2...){
        this.属性 = 形参1;
        ...
        this.方法 = function(){
            ...
        }
    }
        
    var obj = new 构造函数名();    
    ```



### 4. 遍历对象属性

1. `for...in` 遍历对象

2. ```javascript
    for(var k in obj){
        // 输出的是属性/方法名
        console.log(k);
        // 输出对应属性的值或者方法的具体内容
        console.log(obj[k])
    }
    ```

---



## 17. 内置对象

### 1. 对象分类

1. JavaScript 中的对象分为三种：自定义对象、内置对象、浏览器对象。前面两种是 JS 的基础内容，属于 ECMAScript；==第三个浏览器对象是 JS 独有的==。
2. 内置对象不用关心实现过程，注重于使用即可



### 2. 文档查询

1. MDN，包括 HTML， CSS 和万维网（HTTP 等），以及 HTML5 应用的 API



### 3. Math 对象

#### 1. 取最大值函数 max()

1. `Max.max([value1[, value2, value3...]])`
    - 如果给定的参数中有非数字，则返回 `NaN`
    - 如果没有参数，则结果为 `-Infinity`



#### 2. 封装自己的数学对象

1. ```javascript
    var myMath = {
        PI: 3.141592651,
        max: function(){
            var max = arguments[0];
            for(var i = 1; i < arguments.length; i++){
                if(argument[i] > max){
                    max = arguments[i]
                }
            }
            return max;
        }
    }
    ```

2. 然后就和普通的调用对象的属性一样即可，本质上就是对象和对象的属性的使用



#### 3. 绝对值和取整

1. `Math.floor()` 向上取整
2. `Math.ceil()` 向下取整
3. `Math.round()` 四舍五入取整，负数的话，.5反而往大的取
4. `Math.abs()` 取绝对值，会有隐式转换



#### 4. 随机数

1. `Math.random()` 函数返回一个浮点，伪随机数在范围[0, 1)
2. `getRandomInt(min, max)` 得到两个数之间的随机整数，左闭右开



### 4. 日期对象

#### 1. 创建一个日期对象

1. ```javascript
    var date = new Date();
    console.log(date);
    // 输出
    // Sat Dec 18 2021 18:47:45 GMT+0800 (中国标准时间)
    ```



#### 2. 参数常用的写法

1. 数字型

    ```javascript
    var date1 = new Date(2021, 12, 18);
    console.log(date1);
    // 输出
    // Tue Jan 18 2022 00:00:00 GMT+0800 (中国标准时间)
    ```

    - 注意，这里显示的月数比输入的月数大一个月

2. 字符串型

    ```javascript
    var date2 = new Date('2021-12-18 18:56:36')
    console.log(date2);
    // 输出
    // Sat Dec 18 2021 18:56:36 GMT+0800 (中国标准时间)
    ```



#### 3. 日期格式化

1. | 方法名        | 说明                                                    | 代码               |
    | ------------- | ------------------------------------------------------- | ------------------ |
    | getFullYear() | 获取当年                                                | dObj.getFullYear() |
    | getMonth()    | 获取当月(0 - 11)，因此数字型的时候多一个月，0 代表 1 月 | dObj.getMonth()    |
    | getDate()     | 获取当天日期                                            | dObj.getDate()     |
    | getDay()      | 获取星期几（周日 0 到 周六 6）                          | dObj.getDay()      |
    | getHours()    | 获取当前小时                                            | dObj.getHours()    |
    | getMinutes()  | 获取当前分钟                                            | dObj.getMinutes()  |
    | getSeconds()  | 获取当前秒钟                                            | dObj.getSeconds()  |

    

2. 时分秒格式化

    ```javascript
    // 格式化返回一个时分秒
        function getNowTime(){
            var time = new Date();
            var hour = time.getHours();
            hour = hour < 10 ? '0' + hour : hour;
            var minutes = time.getMinutes();
            minutes = minutes < 10 ? '0' + minutes : minutes;
            var seconds = time.getSeconds();
            seconds = seconds < 10 ? '0' + seconds : seconds;
            return hour + ':' + minutes + ':' + seconds;
        }
    ```



#### 4. 时间戳

1. `dObj.valueOf()` 或者 `dObj.getTime()`

2. 或者还可以这样写：

    ```javascript
    var date1 = +new Date();
    ```

3. H5 新增的

    ```javascript
    console.log(Date.now());
    ```



#### 5. 倒计时

1. ```javascript
    // 倒计时
        // 将两个时间转换成时间戳，然后计算差值
        function countDown(date){
            var nowDate = +new Date();
            // var expectedDate = +new Date(date);
            var expectedDate = date.getTime();
            console.log(expectedDate);
            // 先算出所需要的天数（整数部分），然后用取余取到小数部分，再将其转换成对应的时间，然后再取余，再向下重复步骤
            var SecondsSpan = (expectedDate - nowDate) / 1000;
            var seconds = parseInt(SecondsSpan % 60);
            seconds = seconds < 10 ? '0' + seconds : seconds
            var minutes = parseInt(SecondsSpan / 60 % 60);
            minutes = minutes < 10 ? '0' + minutes : minutes
            var hours = parseInt(SecondsSpan /60 / 60 % 24);
            hours = hours < 10 ? '0' + hours : hours
            var days = parseInt(SecondsSpan / 24 / 60 / 60);
            days = days < 10 ? '0' + days : days
            console.log(days + '天' + hours + '时' + minutes + '分' + seconds + '秒');
        }
        var inputDate = prompt('请输入日期');
        inputDate = new Date(inputDate);
        countDown(inputDate);
    ```



### 5. 数组对象

#### 1.检测是否为数组

1. `instanceof` 其可以用来检测是否为数组

    ```javascript
    var arr = [];
    console.log(arr instanceof Array);
    // 输出 true
    ```

2. `Array.isArray()` 也可用用来判断传入的值是否为一个数组（H5 新增的方法）

    ```javascript
    var arr = [];
    console.log(Array.isArray(arr));
    ```



#### 2. 添加数组元素

1. `push()` 在我们数组的==末尾==添加一个或者多个数组元素

    ```javascript
    var arr = [];
    arr.push(1, 2, [1, 2, 3]);
    console.log(arr.length);
    // 长度为3，数组内可以嵌套数组
    // push() 的返回值为新的数组的长度
    ```

2. `unshift()` 在数组的开头添加元素，和 `push()` 一样



#### 3. 删除数组元素

1. `pop()` 删除数组的最后一个元素，返回被删除的元素
2. `shitf()` 删除数组的第一个元素，返回被删除的元素
3. `splice(pos, len)` 从 `pos` 开始（索引），向后删除 `len` 个元素



#### 4. 数组翻转和排序

1. 数组翻转

    ```javascript
    var arr = [1, 2, 3];
    arr.reverse();
    console.log(arr);
    ```

2. 数组排序

    ```javascript
    var arr = [1, 5, 2, 4];
    arr.sort();
    // 冒泡排序，从小到大
    ```

    实际上没有指明比较函数时，默认会把里面的内容转换成 Unicode 位点进行排序，所以需要另写

    ```javascript
    var arr1 = [13, 4, 77, 1, 7];
    arr1.sort(function(a, b){
        // 这个函数表示按照升序的顺序排列
        // 降序的话就是 b - a
        return a - b;
    });
    console.log(arr1);
    ```

    具体详见手册



#### 5. 数组索引方法

1. | 方法名                            | 说明                                       | 返回值                                      |
    | --------------------------------- | ------------------------------------------ | ------------------------------------------- |
    | indexOf('要查找的内容', [索引号]) | 数组中从索引号向后查找给定元素的第一个索引 | 如果存在则返回索引号，如果不存在，则返回 -1 |
    | lastIndexOf()                     | 在数组中的最后一个的索引                   | 同上                                        |



#### 6. 数组转字符串

1. | 方法名         | 说明                                                         | 返回值         |
    | -------------- | ------------------------------------------------------------ | -------------- |
    | toString()     | 把数组转换成字符串，生成的字符串用逗号分隔每一项             | 返回一个字符串 |
    | join('分割符') | 自定义分割符，把所有元素转换成一个字符串，生成的字符串用分割符分割每一项 |                |

2. ```javascript
    var arr = [1, 2, 3];
    console.log(arr.toString());
    // 结果为 1,2,3
    ```

3. ```javascript
    var arr = [1, 2, '3'];
    console.log(arr.join('-'));
    // 输出 1-2-3
    ```



#### 7. 数组的其他方法

1. | 方法名             | 说明                                       | 返回值                             |
    | ------------------ | ------------------------------------------ | ---------------------------------- |
    | concat()           | 连接两个或多个数组，==不影响连接的数组==   | 返回连接后的新数组                 |
    | slice(begin, end)  | 数组从 `begin` 截取，到 `end` 结束         | 返回截取后的新数组，原数组不会改变 |
    | splice(begin, len) | 数组从 `begin` 截取，向后截取 `len` 个元素 | 返回被截取的新数组，==数组被改变== |



### 6. 字符串对象

#### 1. 基本包装类型

1. 基本包装类型就是把简单数据类型包装成为了复杂数据类型，例如：

    ```javascript
    var temp = 'xxx';
    // 等价于
    var temp = new String('xxx');
    ```

2. 过程：

    1. 先创立一个临时变量，假设为 `temp`
    2. 然后把这个临时变量赋值给别的变量，这里假设为 `str`
    3. 然后销毁这个临时变量

    这里用代码表示一下

    ```javascript
    // 以这个为例
    var str = 'xxx'
    // 过程：
    var temp = 'xxx'
    var str = temp;
    temp = null;
    ```



#### 2. 字符串不可变

1. 里面的值不可变，内容变了，实际上是所在的地址发生了变化，在内存中开辟了新的空间



#### 3. 根据字符返回位置

1. 和数组一样，两个方法



#### 4. 根据位置返回字符

1. | 方法名            | 说明                                        | 使用                               |
    | ----------------- | ------------------------------------------- | ---------------------------------- |
    | charAt(index)     | 返回指定位置的字符(index 字符串的索引号)    | str.charAt(0)                      |
    | charCodeAt(index) | 获取指定位置处字符的 ASCII 码(index 索引号) | str.charCodeAt(0)                  |
    | str[index]        | 获取指定位置处字符                          | HTML5，IE8+ 支持和 `charAt()` 等效 |



#### 5. 字符串的操作方法

1. | 方法名                                      | 说明                                             |
    | ------------------------------------------- | ------------------------------------------------ |
    | concat(str1, str2 ...)                      | 一般用 `+` 偏多                                  |
    | substr(start, length)                       | 从 start 开始（索引号），length 为取的个数       |
    | slice(start, end)                           | 从 start 开始，截取到 end 位置，end 那一个取不到 |
    | substring(start, end)                       | 和 slice 差不多，但不接受负数                    |
    | replace('被替换的字符串', '替换成的字符串') | 只替换第一次出现的                               |
    | split('分割符')                             | 字符串转成数组，和 join 的作用相反               |

----



## 18. 数据类型

### 1. 简单数据类型

1. 简单类型又叫做基本数据类型或者**值类型**，复杂类型又叫做**引用类型**。
2. string, number, boolean, undefined，null这些是简单的数据类型。
3. null 为 Object 类型，其为历史遗留问题。

### 2. 复杂数据类型

1. 基本上需要 `new` 的变量都算复杂数据类型，例如 Object, Array, Date...
2. 注意 JS 没有堆栈这种概念。

---



## 19. Web API

### 1. Web APIs 和 JS 基础的关联性

1. 概述：![image-20230117110822276](image-20230117110822276.png)
2. Webn APIs 阶段：
    1. Web APIs 是 W3C 组织的标准。
    2. Web  APIs 主要学习 DOM 和 BOM。
    3. Web APIs 是 JS 中独有的部分。
    4. 主要学习页面交互功能。



### 2. 概念

#### 1. Web API

1. Web API 是浏览器提供的一套操作浏览器功能和页面元素的 API（BOM 和 DOM）。



#### 2. DOM

1. DOM 为文档对象模型（Document Object Model），是 W3C 组织推荐的处理 HTML 或者 XML 的标准编程接口，本质是将文档当作一个对象看待，其顶级对象为 document。
2. W3C 已经定义了一系列的 DOM 接口，通过这些 DOM 接口可以改变页面的内容、结构和样式。
3. DOM 树：
    ![image-20230117111857215](image-20230117111857215.png)

---



## 20. DOM

### 1. 获取元素

#### 1. 常见的获取元素的方法

1. 根据 ID 获取。
2. 根据标签名获取
3. 通过 HTML5 新增方法获取
4. 特殊元素获取



#### 2. 通过 ID 获取

1. 使用 `getElementById()` 来获取。
2. 语法：
    `var element = document.getElementById('id')`。
3. 返回 element 对象（本质就是 Object），找不到返回为 `null`。
4. 注意的是，`getElementById(id)` 的使用必须在 `id` 所在的标签之后才行。
5. `console.dir(element)` 打印元素对象所拥有的属性值。



#### 3. 根据标签名获取

1. 使用 `getElementsByTagName()` 来获取带有指定标签名的对象的集合。
2. 语法:
    `var elements = document.getElementsByTagName('tagName')`
3. 注意获取的内容是动态的，即页面中元素发生变化时，它获取的结果也可能有所不同。
4. 如果页面中，一个对应元素都没有，那么就会返回 `[]`，注意不是 `null`。
5. 同样的，如果想获取一个父 element 下的子 element，语法：
    `父element.getElementByTagName('tagName')`。



#### 4. 使用 HTML5 新增方法（尽量使用这个）

1. 即根据类名来获取：
    `document.getElementsByClassName('className')`。
2. 根据指定选择器返回第一个元素对象：
    `document.querySelector('选择器')`。
    选择器有三个：标签，id（#），类选择器（.）
3. 相应的，有获取全部的：
    `document.querySelectorAll('选择器')`



#### 5. 获取 body 和 html 标签

1. 获取 body 元素对象：
    `var bodyEle = document.body`
2. 获取 html 元素对象：
    `var htmlEle = document.documentElement`



### 2. 事件基础

#### 1. 事件一般编写流程
1. 代码：
    ```js
    js
    // 获取事件源/控件
    var obj = document.getElementById('obj');
    // 决定事件类型和完成事件处理程序
    obj.事件类型 = function(){
        ...
        // 如果这里想对 Obj 进行操作，可以使用 this
    }
    ```



#### 2. 常见的鼠标事件

1. | 鼠标事件    | 触发条件           |
    | ----------- | ------------------ |
    | onclick     | 左键点击           |
    | onmouseover | 鼠标经过触发       |
    | onmouseout  | 鼠标离开出发       |
    | onfocus     | 获得鼠标焦点触发   |
    | onblur      | 失去鼠标焦点时触发 |
    | onmousemove | 鼠标移动触发       |
    | onmouseup   | 鼠标弹起触发       |
    | onmousedown | 鼠标按下触发       |



### 3. 操作元素

#### 1. 改变元素内容

1. 第一种方法：
    `element.innerText`，从起始位置到终止位置的内容，但它不识别 HTML 标签，同时空格和换行也会去掉。
2. 第二种方法：
    `element.innerHTML`，第一个提到的所有去掉的内容全部保留。
3. 以上两个属性是可读的。



#### 2. 修改元素属性

1. 获取元素
2. 注册事件：在匿名函数中修改某元素的属性



#### 3. 修改表单元素的属性操作

1. 利用 DOM 可以操作如下表单的属性：
    type、value、checked、selected、disabled



#### 4. 修改样式属性操作

1. 行内样式操作：`element.style.属性`
    用于修改小样式，小修小改。
2. 类名样式操作：`element.className = 'newClassName'`
    这样子就可以把需要较多变化的 CSS 写在类选择器中，然后使用这个类即可。
    如果想保留多个类，那就使用多类名选择器：
    `element.className = 'oldClassName newClassName'`
    注意不用加 `.`



#### 5. 两种获取属性值的方法

1. `element.属性` 
2. `element.getAttribute('属性')`;



#### 6. 区别

1. 第一种方法获取内置属性值（元素本身自带的属性）。
2. 第二种方法主要获得自定义的属性（标准），获得程序员自定义的属性。



#### 7. 两种设置属性值的方法

1. `element.属性 = '值'`
2. `element.setAttribute('属性', '值')`



#### 8. 区别

1. 第一种方法无法设置 className，而第二种可以。



#### 9. 移除属性

1. `element.removeAttribute`



#### 10. H5 自定义属性（IE 11 以上支持）

1. H5 规定，自定义属性的格式为：
    `data-自定义属性名 = "属性值"`
2. 同时，获取自定义元素又有了新的方法：
    `element.dataset.自定义属性名` 或者 `element.dataset['自定义属性名']`
    注意，自定义属性名前必须有 `data-`。
    dataset 是一个集合，里面存放了所有以 `data-` 开头的自定义属性。
    此外，如果自定义属性名由多个单词组成，例如 `data-my-attribute`。此时就要使用 `myAttribute` 来获取（大驼峰命名法）。



### 4. 节点操作

#### 1. 利用节点关系来获取元素

1. 通过 DOM 提供的 API 获取元素逻辑性不强，繁琐。所以还可以使用节点的层级关系来获取元素。
2. 使用层次关系获取，逻辑性强但兼容性差，不过这个用的多。



#### 2. 节点的概述

1. 一般的，一个节点至少拥有 nodeType、nodeName 和 nodeValue 这三个基本属性。
2. nodeType：
    1. 元素节点为 1，元素就是元素节点。
    2. 属性节点为 2
    3. 文本节点为 3（包含文字、空格、换行，这里的换行不是 `<br>`）
    4. 实际开发中主要操作元素节点。



#### 3. 父子节点

1. 父级节点：`node.parentNode`
2. 子节点：`parentNode.childNodes（标准）`，得到的是集合，注意其包含所有的节点，即包含元素节点和文本节点。
    因此如果要用这个来获取元素节点，比较麻烦，一般不提倡使用。
3. 子节点 2：`parentNode.children（非标准）`，它是一个只读属性，只返回子元素节点的集合；虽然它是非标准，但是各个浏览器基本支持。



#### 4. 父节点的第一个元素和最后一个元素

1. 第一个子节点（包含文本节点）：`parentNode.firstChild`。
2. 最后一个节点（包含文本节点）：`parentNode.lastChild`。
3. 第一个元素子节点：`parentNode.firstElementChild`。
4. 最后一个元素子节点：`parentNode.lastElementChild`。
5. 后两个方法 IE9 以上支持，代替方案：`parentNode.children[...]`



#### 5. 兄弟节点

1. `node.nextSibiling` 返回下一个兄弟节点（包含文本节点）
2. `node.previousSibiling` 返回上一个兄弟节点，找不到返回 `null`，同样包含所有的节点。
3. `node.nextElementSibling` 返回当前元素下一个兄弟元素节点，找不到则返回 `null`。
4. 同样的，有：`node.previousElementSibiling`。



#### 6. 创建节点

1. `document.createElement('tagName')`，动态创建元素节点。
2. 或者用 `element.innerHTML`
3. 注意，如果用 `document.write()`，其直接将内容写入页面的内容流，文档流执行完毕后，会导致页面全部重绘。
4. 使用 `element.innerHTML` 来创建大量元素时，因为本质是字符串拼接，所以效率低于 `document.createElement('tagName')`。
5. 需要注意的是，如果 `element.innerHTML` 采用数组形式转字符串（拼接 `join()`），则效率达到最高；但结构复杂且占一个数组空间。



#### 7. 添加节点

1. `node.appendChild(child)`，类似 CSS 里面的 `after` 伪元素。
2. `node.insertBefore(child, 指定元素)`，在某个元素前，类似 CSS 的 `before` 伪元素。



#### 8. 删除节点

1. 删除父节点的一个子节点 `node.removeChild(child)`。
2. 补充：阻止链接跳转：`href = "javascript:void(0)"` 或者 `href = "javascript:;"`。



#### 9. 复制节点

1. `node.cloneNode(Boolean boolean)`
    如果为空，或者为 `false` ，则为浅拷贝，表示只复制标签，但不复制内容。
    改为 `true` 就是深拷贝。

---



## 21. 事件高级

### 1. 注册事件

1. 传统方式——以 `on` 开头的事件
    特点：注册事件的唯一性，即只能设置一个事件函数。
2. 方法监听注册方式（推荐）。
    使用 `addEventListener()` 。同一个元素同一个事件可以注册多个监听器。
3. 方法监听注册方式（常用）：
    `eventTarget.addEventListener(type, listener, [useCapture])`
    type：事件类型字符串，比如 `click`，`mouseover`，注意不要加 `on`
    listener：事件处理函数
    useCapture（可选）：boolean 类型，默认 `false`，表示在事件冒泡阶段调用事件处理函数，为 `true` 表示在事件捕获阶段调用事件处理函数。具体解释见 DOM 事件流。



### 2. 删除事件（解绑事件）

1. 传统删除方式——`element.onxxx = null`
2. 方法监听删除方式：
    `eventTarget.removeEventListener(type, listener)`



### 3. DOM 事件流

1. 事件流描述的是从页面中接收事件的顺序。
2. 事件发生时会在元素节点之间按照特定的顺序传播，这个传播过程即 DOM 事件流。
    ![image-20230119102134918](image-20230119102134918.png)
3. 传统的注册方式和 `attachEvent(deprecated)` 只能得到冒泡阶段。
4. 一般出现在父子 element 的事件。例如，如果夫 element 的事件和子 element 事件都是捕获阶段发生，那么父 element 的事件将会先于子 element 事件发生。冒泡阶段同理。
5. 实际开发中，很少使用事件捕获，一般更关注事件冒泡。



### 4. 事件对象

1. 监听函数中，如果添加了 `event` 参数，则这个 `event` 就是一个事件对象。
    ```js
    element.onclick = function(event){...}
    ```

2. 只有出现了事件（`onclick` 等等），后面 `event` 形参才会变成事件对象（由系统创建和传递）。

3. `event` 是事件一系列相关数据的集合，和事件相关。

4. 这个 `event` 名字可以改，改成 `e` 也行。

5. 事件对象的常见属性和方法：
    | 事件对象属性方法    | 说明                                                         |
    | ------------------- | ------------------------------------------------------------ |
    | e.target            | 返回触发事件的对象。<br />注意 this 返回的是绑定事件的对象。 |
    | e.srcElement        | 返回触发事件的对象（非标准）                                 |
    | e.type              | 返回事件的类型，比如 click...                                |
    | e.cancelBubble      | 该属性阻止冒泡（非标准）                                     |
    | e.preventDefault()  | 该方法阻止默认事件（默认行为），标准，比如不让链接跳转。     |
    | e.stopPropagation() | 阻止冒泡，标准                                               |



### 5. 事件委托（代理、委派）

1. 原理：不要给每个子节点单独设置监听器，而是事件监听器设置在其父节点上，然后利用冒泡原理影响设置每个子节点，然后如果要获取那个子节点触发了事件，那就使用 `e.target` 来获取。



### 6. 常用的鼠标事件

1. 事件基础中提到的表格。

2. 禁止鼠标右键菜单：
    `contextmenu` 主要控制应该何时显示上下文菜单，主要用于程序员取消默认的上下文菜单：

    ```js
    document.addEventListener('contextmenu', function(e){
        e.preventDefault();
    })
    ```

3. 禁止鼠标选中

    ```js
    document.addEventListener('selectstart', function(e){
        e.preventDefault();
    })
    ```



### 7. 常用的键盘事件

1. 常见的键盘事件：
    | 键盘事件   | 触发条件                                                     |
    | ---------- | ------------------------------------------------------------ |
    | onkeyup    | 某个键盘按键被松开时触发                                     |
    | onkeydown  | 某个键盘按键被按下时触发                                     |
    | onkeypress | 某个键盘按键被按下时触发（但它不识别功能键，例如 ctrl shift 等） |

2. down 优先于 press 执行。

3. keyboardEvent（键盘事件对象）中有一个 `keyCode` 属性，其值为按下的键的 ASCII 值。
    需要注意的是，keyup 和 keydown 两个是不区分大小写的。

---



## 22. BOM

### 1. BOM 概述

1. BOM（Browser Object Model）即浏览器对象模型，它提供了独立于内容而与浏览器窗口进行交互的对象，其核心对象是 window。
2. BOM 由一系列相关的对象构成，并且每个对象都提供了很多方法和属性。
3. BOM 缺乏标准。
4. BOM 将浏览器当作对象模型，把浏览器当作一个对象处理，顶级对象为 window。
5. BOM 主要学习的是浏览器窗口交互的一些对象。



### 2. BOM 构成

1. BOM 包含 DOM：
    ![image-20230119134128055](image-20230119134128055.png)
2. window 对象是浏览器的顶级对象，其：
    既是 JS 访问浏览器窗口的一个接口；又是一个全局对象，定义在全剧作用域中的变量、函数都会变成 window 对象的属性和方法。



### 3. window 常见的事件

#### 1. 窗口加载事件

1. `window.onload = function(){}` 或者 `window.addEventListener("load", function(){})` 。
    `window.onload` 表示窗口（页面）加载事件，当文档内容（各节点）完全加载完成时会触发该事件（包括图片、脚本文件、CSS 等），就调用的处理函数。
2. 有了上述方法，JS 代码就可以写在页面元素的上方。
3. `document.addEventListener('DOMContentLoaded', function(){})`;
    DOMContentLoaded 事件触发时，仅当 DOM 加载完成时触发，不包含图片，CSS，flash 等。



#### 2. 调整窗口大小事件

1. `window.onresize = function(){}` 和 `window.addEventListener("resize", function(){})`。
    只要浏览器窗口大小发生变化，其就会触发事件。



#### 3. 定时器

1. `window.setTimeout(调用/回调函数, [延迟的毫秒数])`。该定时器在定时器到期后执行函数。（`window` 可以省略）
2. `window.clearTimeout(timeID)`，停止定时器。
3. `setInterval(回调函数, [间隔的毫秒数])`，这个方法每隔一段时间重复调用一个函数，注意第一次调用之前还会等一次间隔。
4. 同理 `window.clearIntervel(timeID)` 来实现定时器的清除。



### 4. `this` 指向

1. 一般情况下，`this` 指向函数的调用者。



### 5. JS 执行机制

#### 1. JS 是单线程的

1. JS 语言的一大特点就是单线程，因为 JS 这门脚本语言的使命就是处理页面交互中元素的修改，对某个 DOM 元素进行添加和删除操作，不能同时进行。应该先进行添加，后删除。



#### 2. 同步任务与异步任务

1. 同步任务：都在主线程上执行，形成一个执行栈。

2. 异步任务：JS 的异步是通过回调函数实现的。

3. 常见的异步任务：

    1. 普通事件：click、resize 等
    2. 资源加载：load、error 等
    3. 定时器：包括 setInterval、setTimeout 等。

4. JS 的执行机制：

    1. 先执行执行栈中的同步任务
    2. 异步任务（回调函数）放入任务队列中
    3. 一旦执行栈中的所有同步任务执行完毕，系统就会按照次序读取任务列表中的异步任务，于是被读取的异步任务结束等待状态，进入执行栈，开始执行。
    4. 异步事件一般会交给异步进程处理，当需要执行异步任务时，异步进程就会将异步事件放入任务队列中等待执行。
    5. ![image-20230120110750689](image-20230120110750689.png)
    6. 由于主线程不断的重复获取任务、执行任务、再获取任务、再执行，所以这种机制被称为事件循环。

    

### 6. `location` 对象

#### 1. `location` 对象的定义

1. `window` 对象提供了一个 `location` 属性用于获取或设置窗体的 URL，并且可以用于解析 URL。因为这个属性返回的是一个对象，所以我们将这个属性也称为 `location` 对象。



#### 2. `location` 对象常见的属性

1. | 对象属性 | 返回值                                     |
    | -------- | ------------------------------------------ |
    | href     | 获取或设置整个 URL                         |
    | host     | 返回主机/域名                              |
    | port     | 端口号，没有就返回空字符串                 |
    | pathname | 返回路径                                   |
    | search   | 返回参数（开头为 ？）                      |
    | hash     | 返回片段 # 后的内容（带 # 号），常见于锚点 |



#### 3. `location` 对象的方法

1. | 方法            | 返回值                                                       |
    | --------------- | ------------------------------------------------------------ |
    | assign()        | 和 href 一样，重定向（跳转）                                 |
    | replace()       | 替换当前页面，因为不记录历史，所以不能后退页面               |
    | reload(boolean) | 重新加载页面，相当于刷新按钮或者 f5，如果参数为 true 就强制刷。 |



### 7. `navigator` 对象

1. `navigator` 对象包含有关浏览器的信息，它有很多属性，最常用的就是 `userAgent`，该属性返回 HTTP 头部 `user-agent` 值。



### 8. `history` 对象

1. `window` 对象提供了一个 `history` 对象，与浏览器历史记录进行交互。该对象包含用户（在浏览器窗口中）访问过的 URL。

2. | history 对象方法 | 作用                                              |
    | ---------------- | ------------------------------------------------- |
    | back()           | 后退功能                                          |
    | forward()        | 前进功能                                          |
    | go(参数)         | 前进后退功能，1 为前进一个页面，-1 为后退一个页面 |

