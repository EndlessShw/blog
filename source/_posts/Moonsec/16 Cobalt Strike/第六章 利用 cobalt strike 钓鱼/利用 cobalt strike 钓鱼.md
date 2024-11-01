# 利用 cobalt strike 进行钓鱼攻击

## 1. 宏病毒

1. 宏就是一些命令组织在一起，作为一个单独命令完成一个特定任务。Microsoft Word 中对[宏定义](https://baike.baidu.com/item/宏定义)为：“宏就是能组织到一起作为一独立的命令使用的一系列word命令，它能使日常工作变得更容易”。

2. 宏病毒是利用系统的开放性专门制作的一个或多个具有病毒特点的宏的集合，这种病毒宏的集合影响到计算机的使用，并能通过文档及模板进行自我复制及传播。

3. Attacks --> Packages --> MS Office Macro。然后选择监听器。

4. ![image-20220126111403331](利用 cobalt strike 钓鱼/image-20220126111403331.png)

    复制宏。

5. 根据提示，将宏复制到 Word 中的宏编辑。

6. 将文档另存为启动宏的文档（.docm）



## 2. Windows Executable

1. 生成 windows 可执行程序。打开就可反弹 shell，但是容易被杀。

2. 也可以生成 dll 文件。通过 `regsvr32/64 xxx.dll` ，也就是通过 DllRegisterServer 执行。

    ![image-20220126112627395](利用 cobalt strike 钓鱼/image-20220126112627395.png)



## 3. Windows Executables

1. s 表示 stageless，把包含 payload 在内的 “全功能” 被控端都放入生成的可执行文件，省去了接收 Payload 的步骤。文件体积比较大，三百多 KB 左右。



## 4. System Profiler

1. 它是一种客户端侦察(reconnaissance)工具，通过跳转来掩盖自己的侦察。可以返回用户使用的软件（浏览器）的类型和版本等信息。

2. ![image-20220126115806367](利用 cobalt strike 钓鱼/image-20220126115806367.png)

3. 访问 192.168.43.106/baidu。此时会跳转到百度，并且 cobalt strike 获得信息：

    ![image-20220126120451654](利用 cobalt strike 钓鱼/image-20220126120451654.png)

    