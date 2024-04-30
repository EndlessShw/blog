# Python中的正则表达式

## 1. Python对正则表达式的支持（函数）

Python提供了 ==re 模块== 来支持正则表达式相关操作，下面是 re 模块中的核心函数。

参数解释：

- pattern：正则表达式子

- string：待匹配的字符串

- flags：标志位，用于控制正则表达式的匹配方式。

- repl：替换的字符串，可以为一个函数

- pattern中前面的 r 表示字符串为原始字符串，忽略反斜杠的转义功能

- count：匹配次数，默认为0，表示无限

- | 修饰符      | 描述                                                         |
    | :---------- | :----------------------------------------------------------- |
    | re.I(大写i) | 使匹配对大小写不敏感                                         |
    | re.L        | 做本地化识别（locale-aware）匹配                             |
    | re.M        | 多行匹配，影响 ^ 和 $                                        |
    | re.S        | 使 . 匹配包括换行在内的所有字符                              |
    | re.U        | 根据Unicode字符集解析字符。这个标志影响 \w, \W, \b, \B.      |
    | re.X        | 该标志通过给予你更灵活的格式以便你将正则表达式写得更易于理解。 |

| 函数                                         | 说明                                                         |
| -------------------------------------------- | ------------------------------------------------------------ |
| compile(pattern, flags=0)                    | 编译正则表达式并返回正则表达式==对象==                       |
| match(pattern, string, flags=0)              | 用正则表达式==从头开始==匹配字符串 成功==返回匹配对象== 否则返回 None |
| search(pattern, string, flags=0)             | 搜索字符串中第一次出现正则表达式的模式 成功返回匹配对象 否则返回 None |
| split(pattern, string, maxsplit=0, flags=0)  | 用正则表达式指定的模式分隔符拆分字符串 返回列表              |
| sub(pattern, repl, string, count=0, flags=0) | 用指定的字符串替换原字符串中与正则表达式匹配的模式 可以用 count 指定替换的次数 |
| fullmatch(pattern, string, flags=0)          | match 函数的完全匹配（从字符串开头到结尾）版本               |
| findall(pattern, string, flags=0)            | 查找字符串所有与正则表达式匹配的模式 返回字符串的列表        |
| finditer(pattern, string, flags=0)           | 和 findall() 类似，查找字符串==所有==与正则表达式匹配的模式 返回一个迭代器 |
| purge()                                      | 清除隐式编译的正则表达式的缓存                               |
| re.I / re.IGNORECASE                         | 忽略大小写匹配标记                                           |
| re.M / re.MULTILINE                          | 多行匹配标记                                                 |



## 2. 函数解析

### 1. match()

​		可以使用 group(num) 或 groups() 匹配对象函数来获取匹配表达式。

| 匹配对象方法 | 描述                                                         |
| :----------- | :----------------------------------------------------------- |
| group(num=0) | ==匹配==的整个表达式的==字符串==，group() 可以一次输入多个组号，在这种情况下它将返回一个包含那些组所对应值的元组。 |
| groups()     | ==返回==一个包含所有小组字符串的==元组==，从 1 到 所含的小组号。 |

​		示例代码如下：

```python
"""
re.match() 函数的使用
"""
import re

def main():
    string = "Cats are smarter than dogs."

    # ()表示分组，?表示非贪婪匹配
    pattern = r'(.*) are (.*?) (.*)'

    # 这里形参要么都加，要么全部不加
    matchObj = re.match(pattern=pattern, string=string, flags=re.M | re.I)

    # 如果匹配成功就会返回匹配对象，否则返回None
    if matchObj:
        # span()返回成功匹配的对象在原字符串中的位置
        print("matchObj.span() === ", matchObj.span())
        print("matchObj.group() === ", matchObj.group())
        print("matchObj.group(1) === ", matchObj.group(1))
        print("matchObj.group(2) === ", matchObj.group(2))
        print("matchObj.group(3) === ", matchObj.group(3))
        print("matchObj.group(1, 2, 3) === ", matchObj.group(1, 2, 3))
        print("matchObj.groups() === ", matchObj.groups())
    else:
        print("No match!")

if __name__ == '__main__':
    main();
```



​	运行的结果如下：

```python
matchObj.span() ===  (0, 27)
matchObj.group() ===  Cats are smarter than dogs.
matchObj.group(1) ===  Cats
matchObj.group(2) ===  smarter
matchObj.group(3) ===  than dogs.
matchObj.group(1, 2, 3) ===  ('Cats', 'smarter', 'than dogs.')
matchObj.groups() ===  ('Cats', 'smarter', 'than dogs.')
```



### 2. search()，其与 match 的区别

其用法和 match 差不多，同样也有 group() 和 groups() 方法。

两者区别在于，re.match 只匹配字符串的开始，如果字符串从一开始就不符合正则表达式，则匹配失败，函数返回 None；而 re.search 匹配整个字符串，直到找到一个匹配。

实例代码如下：

```python
"""
match与search的区别
"""
import re

def main():
    string = 'My QQNumber is 1502309758'
    pattern = r'\d+'

    matchObj = re.match(pattern, string, 0)
    if matchObj:
        print("matchObj.group() ===", matchObj.group())
    else:
        print("Match failed!")

    searchObj = re.search(pattern, string, 0)
    if searchObj:
        print("searchObj.group() ===", searchObj.group())
    else:
        print("Search failed")

if __name__ == '__main__':
    main();
```



匹配字符串中的数字，运行结果如下：

```python
Match failed!
searchObj.group() === 1502309758
```



### 3. 检索与替换--sub()

代码例子如下：

```python
"""
repl()的使用
"""
import re

def main():
    string = "今,天,天,气,很,好。"
    pattern = r','
    repl = ''
    # 最大替换次数，0表示全部替换
    count = 0

    newString = re.sub(pattern, repl, string, count, 0)
    print("原字符串为：", string)
    print("替换后的字符串为：", newString)
    
if __name__ == '__main__':
    main();
```



代码结果如下所示：

```python
原字符串为： 今,天,天,气,很,好。
替换后的字符串为： 今天天气很好。
```



### 4. findall()

在字符串中找到正则表达式所匹配的==所有==子串，并返回一个列表，如果没有找到匹配的，则==返回空列表==。

对于 match() 和 search()，这两者时匹配一次，而 findall() 则是匹配所有。

代码实例：

```python
"""
findall()示例
"""
import re

def main():
    string = "嘉然捏，今晚吃什么捏"
    pattern = r'(捏)'

    searchObj = re.search(pattern, string)
    if searchObj:
        print("匹配到捏：", searchObj.groups())
    else:
        print("嘉然今天没有捏")

    findallObj = re.findall(pattern, string)
    if findallObj:
        print("匹配到捏：", findallObj)
    else:
        print("嘉然今天没有捏")

if __name__ == '__main__':
    main();
```



输出的结果为：

```python
匹配到捏： ('捏',)
匹配到捏： ['捏', '捏']
```



### 5. compile()

compile() 函数主要是用于编译正则表达式，生成一个正则表达式对象，供 match()、search() 和 findall() 使用(主要是这几个，其他的方法也行)。

生成的对象使用方法时，里面的参数有所变化。代码如下所示。

```python
"""
compile()的使用
"""
import re

def main():
    compileObj = re.compile(r'\d+')
    string = "abc1234def56g,h7i89"

    matchObj = compileObj.match(string)
    if matchObj:
        print("matchObj从头开始匹配 === ", matchObj.groups())
    else:
        print("matchObj从头开始匹配为空")

    matchObj = compileObj.match(string, 3, 7)
    if matchObj:
        print("matchObj从第4位开始匹配，到第7位 === ", matchObj.group())
    else:
        print("matchObj从第4位开始匹配为空")

    searchObj = compileObj.search(string)
    print("searchObj从头开始匹配 === ", searchObj.group())

    subObj = compileObj.sub("fuck", string)
    print("用fuck替换所有的数字为：", subObj)

    findallObj = compileObj.findall(string)
    print("findall匹配多次：", findallObj)

if __name__ == '__main__':
    main();
```



匹配的结果如下所示：

```python
matchObj从头开始匹配为空
matchObj从第4位开始匹配，到第7位 ===  1234
searchObj从头开始匹配 ===  1234
用fuck替换所有的数字为： abcfuckdeffuckg,hfuckifuck
findall匹配多次： ['1234', '56', '7', '89']
```



compile() 的作用在于，在多次需要使用正则表达对象（也就是 pattern ）时，==预编译一次==，否则每次使用一次都得编译一次，实现高效率。

但是由于大部分函数自带 compile() 的实现，而且都==自带缓存==，它会自动储存最多 512 条由 type(pattern), pattern, flags) 组成的 Key，只要是同一个正则表达式，同一个 flag，那么调用两次_compile 时，第二次会直接读取缓存。所以除非记录很多，否则可以不用 compile()



### 6. split() 

不多逼逼，直接代码实例：

```python
"""
split()使用
"""
import re

def main():
    pattern = r'\W+'
    string = 'wasd, qwer, 4399'
    splitObj = re.split(pattern, string)
    print("原字符串为：", string)
    print("分割后生成的列表为：", splitObj)

if __name__ == '__main__':
    main()
```



结果如下所示：

```python
原字符串为： wasd, qwer, 4399
分割后生成的列表为： ['wasd', 'qwer', '4399']
```



## 3. 正则表达式模式

| 模式        | 描述                                                         |
| :---------- | :----------------------------------------------------------- |
| ^           | 匹配字符串的开头                                             |
| $           | 匹配字符串的末尾。                                           |
| .           | 匹配任意字符，除了换行符，当re.DOTALL标记被指定时，则可以匹配包括换行符的任意字符。 |
| [...]       | 用来表示一组字符,单独列出：[amk] 匹配 'a'，'m'或'k'          |
| [^...]      | 不在[]中的字符：[^abc] 匹配除了a,b,c之外的字符。             |
| re*         | 匹配0个或多个的表达式。                                      |
| re+         | 匹配1个或多个的表达式。                                      |
| re?         | 匹配0个或1个由前面的正则表达式定义的片段，非贪婪方式         |
| re{ n}      | 精确匹配 n 个前面表达式。例如， **o{2}** 不能匹配 "Bob" 中的 "o"，但是能匹配 "food" 中的两个 o。 |
| re{ n,}     | 匹配 n 个前面表达式。例如， o{2,} 不能匹配"Bob"中的"o"，但能匹配 "foooood"中的所有 o。"o{1,}" 等价于 "o+"。"o{0,}" 则等价于 "o*"。 |
| re{ n, m}   | 匹配 n 到 m 次由前面的正则表达式定义的片段，贪婪方式         |
| a\| b       | 匹配a或b                                                     |
| (re)        | 对正则表达式分组并记住匹配的文本                             |
| (?imx)      | 正则表达式包含三种可选标志：i, m, 或 x 。只影响括号中的区域。 |
| (?-imx)     | 正则表达式关闭 i, m, 或 x 可选标志。只影响括号中的区域。     |
| (?: re)     | 类似 (...), 但是不表示一个组                                 |
| (?imx: re)  | 在括号中使用i, m, 或 x 可选标志                              |
| (?-imx: re) | 在括号中不使用i, m, 或 x 可选标志                            |
| (?#...)     | 注释.                                                        |
| (?= re)     | 前向肯定界定符。如果所含正则表达式，以 ... 表示，在当前位置成功匹配时成功，否则失败。但一旦所含表达式已经尝试，匹配引擎根本没有提高；模式的剩余部分还要尝试界定符的右边。 |
| (?! re)     | 前向否定界定符。与肯定界定符相反；当所含表达式不能在字符串当前位置匹配时成功 |
| (?> re)     | 匹配的独立模式，省去回溯。                                   |
| \w          | 匹配字母数字及下划线                                         |
| \W          | 匹配非字母数字及下划线                                       |
| \s          | 匹配任意空白字符，等价于 **[ \t\n\r\f]**。                   |
| \S          | 匹配任意非空字符                                             |
| \d          | 匹配任意数字，等价于 [0-9].                                  |
| \D          | 匹配任意非数字                                               |
| \A          | 匹配字符串开始                                               |
| \Z          | 匹配字符串结束，如果是存在换行，只匹配到换行前的结束字符串。 |
| \z          | 匹配字符串结束                                               |
| \G          | 匹配最后匹配完成的位置。                                     |
| \b          | 匹配一个单词边界，也就是指单词和空格间的位置。例如， 'er\b' 可以匹配"never" 中的 'er'，但不能匹配 "verb" 中的 'er'。 |
| \B          | 匹配非单词边界。'er\B' 能匹配 "verb" 中的 'er'，但不能匹配 "never" 中的 'er'。 |
| \n, \t, 等. | 匹配一个换行符。匹配一个制表符。等                           |
| \1...\9     | 匹配第n个分组的内容。                                        |
| \10         | 匹配第n个分组的内容，如果它经匹配。否则指的是八进制字符码的表达式。 |

------

### 正则表达式实例

#### 字符匹配

| 实例   | 描述           |
| :----- | :------------- |
| python | 匹配 "python". |

#### 字符类

| 实例        | 描述                              |
| :---------- | :-------------------------------- |
| [Pp]ython   | 匹配 "Python" 或 "python"         |
| rub[ye]     | 匹配 "ruby" 或 "rube"             |
| [aeiou]     | 匹配中括号内的任意一个字母        |
| [0-9]       | 匹配任何数字。类似于 [0123456789] |
| [a-z]       | 匹配任何小写字母                  |
| [A-Z]       | 匹配任何大写字母                  |
| [a-zA-Z0-9] | 匹配任何字母及数字                |
| [^aeiou]    | 除了aeiou字母以外的所有字符       |
| [^0-9]      | 匹配除了数字外的字符              |

