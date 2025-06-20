---
title: 某乙方安全运营实习经验总结
categories:
- Working_Experience
tags:
- Working_Experience
date: 2025-06-19 16:29:58
---

# 某乙方安全运营实习经验总结

1. 三个月实习，小小总结一下，也算是学了一点东西吧。
2. 主要的内容还是偏蓝队中级，也没机会接触到应急响应，如果实习超过这个点的话，就有机会接触应急了吧。
3. 不过运营还是不推荐干，转安研、安开、AI 才是正道。

## 1. 安全设备

1. 安全设备的部署一般是 SSE、UTS 作为网络探针，并联在出入口防火墙上。
2. 大量小型客户都会有本地的 ESP-H 或 ISOP 态势感知平台，这些平台连接客户本地的流量探针设备，从而进行告警等相关工作。然后有统一的一个大的云端 ISOP，通过隧道连接这些本地态势感知平台以作更进一步的汇总。
3. 不论是汇总的态势感知平台，还是中大型客户本地的，最终都会通过隧道连接到云端的 Tone 平台以便蓝队成员进行流量分析和威胁研判，同时云端也可以下方指令等。

## 2. 主要工作内容

### 2.1 设备的巡检维护

1. 首先就是要保证隧道的连通性。云端人员是可以通过隧道进入到具体客户的态势感知平台，同时本地事件提取到云端也是需要通过隧道，因此隧道的连通性是关键。
2. 保证客户本地的流量探针以及防火墙等设备的在线状态。否则无法获取到流量和日志。

### 2.2 威胁分析

1. 主要处理云端提取的事件，这些事件是关键事件，危害性高。

### 2.3 文书工作

1. 出现沦陷或者有风险的地方，及时通知客户。
2. 周月报的编写。

### 2.4 策略优化和加白

1. 更具业务或者威胁分析后发现某些特定行为或者流量是正常行为时，就要对其进行加白。

## 3. 经验总结

1. 主要内容就在这个地方了，主要分为三个方面：研判经验、一些知识点以及客户交流经验。

### 3.1 研判经验

#### 3.1.1 日常

1. 除了告警，学会查看日志。更具原目 IP、端口、告警中涉及的流量关键字、时间等维度进行筛选。
2. 多用 wireshark 进行流量取证，查看流的具体内容。设备没有响应码不代表真没有，具体还是要看日志和流量取证。
    木马文件可以下载后审计。
3. 平台所给出的响应体内容代表的是 HTTP 的响应体，因此某些流量如果只走到了 TCP，那么就必须借助取流和日志。
4. 判断是否为攻击时，除了从告警的角度来想，也可以从业务和攻击者的角度考虑问题。可以借助以下方向：
    1. 客户群内是否已有报备；
    2. 目的主机画像，包括但不限于：是服务器还是办公 PC（例如周六日是否有流量产生）、是否是 Nginx 代理服务器、是否是 DNS 中转服务器等。
    3. 通过日志查看攻击的持续周期多久，是否是每天的固定行为。源 IP 是否有对其他资产交互。

#### 3.1.2 失陷后的攻击链回溯

1. 依据常规经验定位到失陷告警时，需要有以下注意的地方：
    1. 需要判断攻击者使用失陷点做了哪些事情，包括但不限于上传了具体哪些 Webshell，进一步的信息探测等。
    2. 注意失陷体的请求头，着重关注有没有 Cookie 或 Auth 头等身份信息，如果有，则表明其可能是有权限的，那么真正的源头失陷处可能并不是当前的地方，还需要进一步回溯。
2. DNSLog 失陷相关注意点：
    1. 注意具体失陷的主机是哪一台，由于流量探针设备可能并不能完全覆盖到所有流量（主机），因此抓到的流量可能是中转 DNS 的请求，因此还需要定位到真正的失陷主机。
    2. DNS 回答段是会给出域名对应的 IP，可以查是否有主机回连该 IP，从而辅助定位失陷主机。
    3. 从攻击者的角度想，同时间段的攻击/漏扫，一般只用一个 DNSLog，以域名为关键字进行查找也可以辅助定位失陷主机。
3. C2 IP 的判断，可以从日志中的“心跳特征”辅助判断，同时可以结合情报、开放端口以及 C2 检测工具。

### 3.2 客户总结

1. 安全这边有关设备的问题要避免和客户同步，直接通知前场人员或者项目经理。尤其是服务到期、设备证书到期和设备离线情况。不然有些客户就喜欢抓“尾巴”。（变相卖队友）
2. 不是自己的业务范围尽量不要说这边处理啥的，不要把责任“揽在自己身上”，总之多用“协调”这两个字。

### 3.3 加白和策略优化

1. 加白就是按照五元组加白（源目 IP 和端口、事件 ID），优先在本地平台上加白，注意优先在“威胁研判”处加白，即事件加白但是日志存在，防止加白后真出事了还有可以回溯的地方。
2. 以目前接触的来看，策略优化其实就是变相加白。而且由于有云端二次提取的存在，策略优化基本也是为了给客户写策略优化报告。一般策略优化都有优化方法和报告模板，不过本质是这些规则的误报率非常之高，极少数是攻击，因此可以“优化”。
3. 此外还可以配置自动研判策略，主要是云端所提取的事件中，已经攻击失败，但是基本每天都会告警的事件，就可以使用自动研判。当然某些客户对挖矿不进行处理，一直有“挖矿域名请求”的，也可以自动研判。

### 3.4 零碎知识点

1. CyberChef AES 解密没有 Base64 解密。所以如果需要，先进行标准 Base64 解密，然后再 AES 解密，最后下载 class 源码，并进行反编译。
2. 注意 HTTP 包头的一些字段，XFF 或者 X-real-IP 可能会揭示真实 IP，或者反映当前的代理配置。Host 也可以用于辅助判断是否为正常业务或者反代。
    有关反代的问题详见：https://blog.csdn.net/xiao__gui/article/details/83054462
    大概是：在对外 Nginx 反代设置合理的情况下，伪造的 XFF 会被覆盖，直接替换成真实的 IP。（这时对外的反代服务器 IP 并没有追加上去）。
    有反代时，XFF 正常都是多于 1 个，伪造 XFF 时就是 >= 1 个。因此如果请求是内对内的，那么 XFF 必定有真的。
3. DGA 域名，常见于恶意脚本。通过批量生成子域名来躲避情报的审查，脚本反向连接时，通过 DGA 算法，把恶意域名都发起请求，只要其中有部分域名是攻击者注册且利用的，就可以发起反向连接。
4. 序列化数据解析工具：[zkar](https://github.com/phith0n/zkar)。

## 4. 后记

1. 多的暂时也想不起来了，总之还有一些涉及到具体客户内容的沦陷/分析报告，也不能在博客中提及。
2. 就这样吧，学了点内容，但也只是一点。加油冲安开！
