---
title: Android_NFC
categories:
- Android
- NFC
tags:
- NFC
date: 2024-01-29 11:27:47
---

# NDEF数据的操作

- 从NFC标签读取NDEF格式的数据
- 向NFC标签写入NDEF格式的数据
- 通过Android Beam技术将NDEF数据发送到另一部NFC设备（非视频等大型二进制文件）



# NFC的三重过滤机制

在一个NFC设备读取NFC标签或者另一个NFC设备中的数据之前，会==在0.1秒内==建立NFC连接，然后数据会自动从被读取的一端流向读取数据的一端（NFC设备一般需要触摸一下屏幕才开始传输）。数据接收端会根据==具体的数据格式和标签类型调用相应的Activity==（这种行为也称为Tag Dispatch）。这些Activity都需要定义Intent Filter。这些Intent Filter中就会指定不同的过滤机制，分为==三个级别==。因此，也成为NFC的三重过滤机制。



## 三种过滤机制

NDEF_DISCOVERED:只过滤固定格式的NDEF数据。比如，纯文本、指定协议（http、ftp、smb等）的URI等。

TECH_DISCOVERED:当NDEF_DISCOVERED指定的过滤机制无法匹配Tag时，就会使用这种过滤机制进行匹配。这种过滤机制并不是通过Tag中的数据格式进行匹配的，而是==根据Tag支持的数据存储格式进行匹配==。因此这种过滤机制的范围更广。

TAG_DISCOVERED:如果前两种都不能过滤，那么就会用这种过滤机制来处理。这种过滤机制是用来处理未识别的Tag（数据格式不对，而且Tag支持的格式也不匹配）。

成功匹配，发出清脆的声音，反之沉闷的声音。
