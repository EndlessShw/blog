---
title: JQuery
categories:
- Front end
- HTML_CSS_JS_JQuery
tags:
- Front end
date: 2024-01-10 14:00:32
---

# JQuery

## 1. jQuery 概述

### 1. JavaScript 库

1. jQuery 就是一个 JS 库，其就是为了快速方便的操作 DOM，里面都是一些方法。

### 2. 其他常见的 JS 库

1. ProtoType
2. YUI
3. Dojo
4. Ext JS
5. 移动端的 zepto

### 3. jQuery(JS Query) 概述

1. jQuery 对 DOM 操作进行封装，封装了 JS 常用的功能代码，优化了 DOM 操作、时间处理、动画设计和 AJAX 交互。
2. 学习 jQuery 的本质就是学习调用方法。

## 2. jQuery 的简单使用

### 1. 导入

1. 直接在官网上下载，然后将代码复制到 .js 文件中，随后在需要使用的页面中导入即可：
    ```html
    <script src="jQuery.js"></script>
    ```

### 2. 入口函数

1. 写法一（用的多）：

    ```js
    $(function(){
        // 此处是页面 DOM 加载完成后执行的内容
        ...
    })
    ```

2. 写法二：
    ```js
    $(document).ready(function(){
        // 此处是页面 DOM 加载完成后执行的内容
        ...
    })
    ```

3. 以上两种方法相当于原生 JS 中的 `DOMContentLoaded`，但不同于原生 JS 中的 `load`，`load` 是 DOM、外部 JS、CSS 文件、图片等加载完毕后才执行的代码。

### 3. jQuery 顶级对象

1. `$` 是 JQuery 的别称，在代码中可以使用 jQuery 代替 `$` ，但一般直接用 `$` 符号。例如上面入口函数，可以写成：`jQuery(function(){})`
2. `$` 是 jQuery 的顶级对象，相当于原生 JS 中的 `window`。利用 `$` 可以把原生的 JS 对象包装成 jQuery 对象，此时就可以调用 jQuery 中的方法。例如：
    `$('标签名，例如 div ').jQuery中的方法()`

### 4. DOM 对象和 jQuery 对象。

1. 获取对象：
    ```js
    // 1. DOM 获取对象（这里用标签选择器举例）：
    var obj = document.querySelector('div');
    // 2. jQuery 获取对象，用 jQuery 方式获取获取的是 jQuery 对象。本质是通过 $ 把 DOM 元素中常见的元素进行了包装，以伪数组的形式存储
    $('div');
    ```

2. 注意：jQuery 对象只能用 jQuery 方法，原生 DOM 对象只能用原生的 JS 方法，两者不能混用。

3. 两者相互转换：
    ```js
    // DOM 转 jQuery 对象：
    $(DOM 对象)
    // jQuery 转 DOM，一般 index 为 0
    $('')[index] 或者 &('').get(index);
    ```

## 3. jQuery 常用 API

### 1. jQuery 基础选择器

1. jQuery 给获取元素的方式进行了封装，使获取元素统一标准：
    ```js
    $("选择器") // 里面选择器直接写 CSS 选择器即可，但是需要加引号
    ```

2. 常见选择器及其获取：
    | 名称       | 用法            | 描述                    |
    | ---------- | --------------- | ----------------------- |
    | ID 选择器  | $("#id")        | 获取指定 ID 的元素      |
    | 全选选择器 | $('*')          | 匹配所有元素            |
    | 类选择器   | $(".class")     | 获取同一类 class 的元素 |
    | 标签选择器 | $("div")        | 获取同一标签的所有元素  |
    | 并集选择器 | $("div, p, li") | 选取多个元素            |
    | 交集选择器 | $("li.current") | 交集元素                |

3. 层级选择器：
    | 名称       | 用法         | 说明                                           |
    | ---------- | ------------ | ---------------------------------------------- |
    | 子代选择器 | $("ul > li") | 获取亲儿子层级的元素，但不会获取孙子层级的元素 |
    | 后代选择器 | $("ul li")   | 获取 ul 下所有的 li 元素，包括孙子。           |

### 2. jQuery 隐式迭代

1. jQuery 设置样式：
    ```js
    $('div').css('属性', '值')
    ```

    这样设置后，获取到的所有的元素的 CSS 都会发生改变。如果是原生 JS，则需要迭代遍历，每个单独设置，而 jQuery 给匹配到的所有元素进行循环遍历，而不需要程序员再进行循环，这个过程就是隐式迭代。

### 3. jQuery 筛选选择器

1. 常见的筛选选择器：
    | 语法       | 用法          | 描述                                                       |
    | ---------- | ------------- | ---------------------------------------------------------- |
    | :first     | $('li:first') | 获取第一个 li 元素                                         |
    | :last      | $('li.last')  | 获取最后一个 li 元素                                       |
    | :eq(index) | $("li:qu(2)") | 获取到的 li 元素中，选择索引号为 2 的元素，索引从 0 开始。 |
    | :odd       | $("li:odd")   | 获取到的 li 元素中，选择索引号为奇数的元素                 |
    | :even      | $("li:even")  | 获取到的 li 元素中，选择索引号为偶数的元素                 |

### 4. jQuery 筛选方法

1. 常见的筛选方法：
    | 语法               | 用法                       | 说明                                                   |
    | ------------------ | -------------------------- | ------------------------------------------------------ |
    | parent()           | $("li").parent()           | 查找父级                                               |
    | children(selector) | $("ul").children("li")     | 相当于 $("ul > li") 子代选择器，选择最近一级（亲儿子） |
    | find(selector)     | $("ul").find("li")         | 相当于$("ul li")，后代选择器                           |
    | siblings(selector) | $(".first").siblings("li") | 查找兄弟节点，不包括自己本身                           |
    | nextAll([expr])    | $(".first").nextAll()      | 查找当前元素之后所有的同辈元素                         |
    | prevtAll([expr])   | $(".last").prevAll()       | 查找当前元素之前所有的同辈元素                         |
    | hasClass(class)    | $('div').hasClass("类名")  | 检查当前的元素是否含有某个特定的类，如果有则返回 true  |
    | eq(index)          | $("li").eq(2)              | 相当于 $("li:eq(2)")                                   |

2. 排他思想：原生的 JS 使用“排他思想”时，需要使用 `for` 循环，而在jQuery 中，使用“隐式迭代”配合 `siblings` 筛选方法可以实现“排他思想”

### 5. jQuery 修改 CSS

1. 简易修改（操作 CSS 方法）：
    `$(this).css("key", "value");`
    以对象的形式：`$(this).css({"key1": "value1", "key2": "value2"...});`
2. 设置类样式方法：
    1. 添加类：
        `$("筛选过滤器").addClass("className");`
    2. 删除类：
        `$("筛选过滤器").removeClass("className");`
    3. 切换类（没有就加上，有则去掉）：
        `$("筛选过滤器").toggleClass("className");`
3. 类操作和属性 `className` 区别
    类操作一般是增加类名，而原生 JS 的 `className` 会覆盖原先的类名。

### 6. jQuery 属性操作

1. 获取元素固有属性值 `prop("属性")`。
2. 设置元素固有属性值 `prop("属性", "属性值")`
3. 获取元素自定义的属性值 `attr("属性")`
4. 同理，设置为：`attr("属性", "属性值")`

### 7. 数据缓存

1. `data()` 方法可以在指定的元素上存取数据，并不会修改 DOM 元素结构。一旦页面刷新，之前存放的数据都将会被移除。

    ```js
    // 设置
    $("选择器").data("key", "value");
    // 获取
    $("选择器").data("key");
    ```

### 8. jQuery 内容文本值（针对元素内容和表单的值的操作）

1. 普通元素内容 `html()`（相当于原生的 `innerHTML`）
    ```js
    // 获取元素内容
    $("选择器").html();
    // 设置元素内容
    $("选择器").html("内容");
    ```

2. 普通元素文本内容 `text()` （相当于原生的 `innerText`）
    ```js
    $("选择器").text()
    $("选择器").text("内容")
    ```

3. 设置表单元素中的表单值 `val()`
    ```js
    $("选择器").val()
    $("选择器").val("内容")
    ```

### 9. jQuery 的元素操作（遍历、创建、添加、删除）

1. 遍历：jQuery 隐式迭代是对同一类元素做相同操作，如果想给同一类元素做不同操作，就要使用遍历。
    `$("选择器").each(function(index, domEle){ ...;})`
    1. `each()` 方法遍历匹配的每一个元素，主要用 DOM 处理，`each` 每一个。
    2. 里面回调函数有 2 个参数：`index` 是每个元素的索引号，`domEle` 是每个 DOM 元素对象，不是 jQuery 对象。两个参数的名字可以改。
2. 除此之外，还有方法：
    `$.each(object/$("选择器"), function(index, element){ ...; })`
    1. 该方法可以遍历任何对象，即数组、对象等其他数据结构可以通过该方法遍历。
3. 创建元素：
    `$("想要创建的元素标签，例如 <li></li>")`
4. 添加元素：
    1. 内部添加：
        `element.append(元素对象)`，放在匹配的元素内部的后面，相当于原生的 `appendChild`。`element.prepend(元素对象)`，放在元素内的前面。
    2. 外部添加：
        `element.after("内容")` 和 `element.before("内容")`。
5. 删除元素
    1. `element.remove()` 删除匹配的元素（自身）
    2. `element.empty()` 删除匹配的元素集合中所有的子节点。
    3. `element.html("")` 清空匹配的元素内容。

... 还有很多和效果相关的 api，这里暂时略过。

## 4. jQuery 事件

### 1. 单个事件注册

1. 基本和原生 JS 一致：
    ```js
    // 原生
    element.事件(function(){...});
    // jQuery
    $("选择器").click(function(){...});
    ```

2. jQuery 用 `on()` 绑定一个或多个事件处理函数
    语法：`element.on(events, [selector], fn);`

    1. `events` ，一个或者多个用空格分隔的事件类型，如 `click` 或者 `keydown`。
    2. `selector`，元素的子元素选择器。
    3. `fn`：回调函数。

3. 多个事件绑定不同处理程序语法：
    ```js
    $("选择器").on({
        事件1: function(){},
        事件2: function(){}...
    })
    ```

4. 多个事件绑定相同程序：
    ```js
    $("选择器").on("事件1 事件2", function(){})
    ```

5. 使用 `on()` 还可以实现事件委派操作，将子元素身上的事件绑定在父元素身上。

    `$("选择器").on("event", "子元素", function(){})`
    事件绑定在父选择器上，但触发的对象是子元素。

6. 使用 `on()` 还可以给未来动态生成的元素绑定事件

7. 使用 `one()` 绑定的事件，只能触发一次。

### 2. 事件解绑

1. 使用 `off()` 移除 `on()` 方法添加的事件。
2. 解除所有事件：
    `$("选择器").off()`
3. 解除特定事件：
    `$("选择器").off("event")`
4. 解除事件委托：
    `$("选择器").off("event", "子元素")`

### 3. 自动触发事件

1. 第一种方式：
    `element.event()`
2. 第二种方式：
    `element.trigger("event")`
3. 第三种方式：
    `element.triggerHandler("event")`
4. 第三种方式不会触发元素的默认行为（例如表单获得焦点后光标闪烁）。

### 4. 事件对象

1. 用 `on()` 绑定事件时，里面的 `function()` 可以有参数 `function(event)`，即事件对象。
2. 事件对象常用的一些属性：
    1. 阻止默认行为：`event.preventDefault()` 或 `return false`
    2. 阻止冒泡：`event.stopPropagation()`。







