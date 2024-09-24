---
title: Python 相关漏洞
categories:
- Network_Security
- Web
- Python_Security
tags:
- Network_Security
- Python
date: 2024-09-24 17:03:04
---

# Python 有关的安全

## 1. Flask 的 PIN 码

1. 参考文章：

    > https://adam8en.github.io/2023/11/06/CTF%E9%97%AE%E9%A2%98%E9%9B%86/%E4%B8%80%E6%96%87%E5%BC%84%E6%B8%85%E6%A5%9AFlask%E6%A1%86%E6%9E%B6%E4%B8%8B%E8%AF%A5%E5%A6%82%E4%BD%95%E8%AE%A1%E7%AE%97PIN%E7%A0%81/

    文章讲的很清楚。

2. 例题：
    [GYCTF2020]FlaskApp 1

## 2. Pickle 的反序列化漏洞

1. 原理不是很复杂，这篇文章讲的很清楚：

    > https://blog.csdn.net/qq_39947980/article/details/137033740

2. 注意 payload 的生成环境，Python2 和 3 经过 URL 编码后的结果不同。

## 3. PyYaml 反序列化漏洞

1. 参考文章：

    > https://xz.aliyun.com/t/12481?time__1311=GqGxRQqiuDyDlrzG78KG%3DGC9wE5WuepD&u_atoken=e289de62ffad3edd58b1962b2be28946&u_asig=ac11000117270828592812553e0047#toc-5

    TODO 以后再学

2. 参考例题：[TSCTF-J2024]alpaca_search_again

## 4. Python 原型链污染

1. 参考文章：

    > https://xz.aliyun.com/t/13072?u_atoken=c65aecab27cdf6d2023eafe3b2adc879&u_asig=ac11000117268316071081875e0044&time__1311=CqIx0DBDRDcD97D2DBuQwqpqh7YitrettH4D

2. 思想基本和 JS 的原型链污染类似，常见的危险函数：
    ```python
    def merge(src, dst):
        # 遍历源的键值对？
        for k, v in src.items():
            # 如果 dst 有 __getitem__
            if hasattr(dst, '__getitem__'):
                if dst.get(k) and isinstance(v, dict):
                    merge(v, dst.get(k))
                else:
                    dst[k] = v
            elif hasattr(dst, k) and isinstance(v, dict):
                merge(v, getattr(dst, k))
            else:
                setattr(dst, k, v)
    ```

3. 关键点在于找目标类，切入（可以被修改的对象）和想要修改的对象之间尽量要有关系，当然也不一定，Python 相对于 JS，有了 `__init__` 可以获取到全局变量，sys 模块中的 module 属性也可以访问其他的模块（从而可以污染）。总之范围可以影响的范围应该更广。

4. 详细例题：[TSCTF-J2024]我闻到了[巧物]的清香
