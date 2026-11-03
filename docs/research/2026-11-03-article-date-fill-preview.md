# 现有文章发布时间补齐预览

生成日期：2026-11-03。仅生成文档，尚未修改文章、配置或部署。

范围：根仓库跟踪的 source/_posts/ 下 124 个 Markdown。保留已有 date 的 43 个文件，仅为缺失 date 的 81 个文件提出补齐值；8 个被忽略的工程 HELP.md 和 1 个子模块 README.md 不纳入本轮迁移，其他目录不动。

时间来源：沿重命名追溯后的首次可追溯 Git 提交，采用提交者时间，统一换算为北京时间。候选值是推定发布时间，不是已证实的真实首发时间；历史中被移除或改写的 date 不用于本轮恢复。

写入边界：有 front matter 时仅添加 date；无 front matter 时添加只含 date 的必要头部。保留正文、原有字段、编码和 CRLF/LF 格式，不新增动态 updated。日期字段维护不算内容更新。

本阶段仅处理发布时间补齐。基于有效内容和附件历史自动派生 updated、统一构建时区及修正旧更新脚本属于后续实现；不能将本预览理解为整个日期问题已修复。

## 拟补齐的 81 个文件

| 文件（相对 source/_posts/） | 拟补 date（北京时间） | 来源提交 | 操作 |
| --- | --- | --- | --- |
| Android/AndroidP8_Provider/内容提供者.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| Android/AndroidP9_InternetProgram/网络编程.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Android/Android_项目_领卷联盟/领卷联盟.md | 2023-12-29 17:32:41 | [23f63cf](https://github.com/EndlessShw/blog/commit/23f63cf2f51447c0a1c9fd21f08b45abd7e4309a) | 添加仅含 date 的头部 |
| Cryptography/北邮密码学面试.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Golang/TelerWaf/面试准备.md | 2026-04-13 16:41:08 | [cdcc145](https://github.com/EndlessShw/blog/commit/cdcc1453fade80d41e7e374dbb6917546dbd976c) | 在现有头部补 date |
| HTML_CSS_JS_JQuery/CSS/CSS.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Interview_Experience/京东.md | 2026-04-13 16:41:08 | [cdcc145](https://github.com/EndlessShw/blog/commit/cdcc1453fade80d41e7e374dbb6917546dbd976c) | 在现有头部补 date |
| Java&JavaWeb/AJAX/AJAX.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Java&JavaWeb/AJAX/笔记/AJAX.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| Java&JavaWeb/JavaSE进阶/JavaSE进阶.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Java&JavaWeb/JavaWeb/JavaWeb.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Java&JavaWeb/JavaWeb/参考笔记/Servlet-JSP-课堂笔记.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| Java&JavaWeb/Maven/Maven.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Moonsec/16 Cobalt Strike/第三章 DNS Beacon的使用与原理/DNS Beacon的使用和原理.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Moonsec/16 Cobalt Strike/第五章 会话管理/会话管理.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Moonsec/16 Cobalt Strike/第六章 利用 cobalt strike 钓鱼/利用 cobalt strike 钓鱼.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Moonsec/16 Cobalt Strike/第四章 用户驱动攻击/用户驱动攻击.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| MySQL/MySQL 笔记.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| NFC/Android_NFC.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Internet/HTTPS/SSL_TLS.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Internet/L7VPN/SSL_VPN.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Internet/Proxy/Proxy.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Intranet/Cobalt_Strike/Cobalt_Strike.md | 2024-09-24 17:57:32 | [7ee43b2](https://github.com/EndlessShw/blog/commit/7ee43b23e718ca372311742d56c8a9eeb10e3026) | 在现有头部补 date |
| Network_Security/SRC/CORS/CORS.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/SRC/Concurrent/Concurrent.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/SRC/JS/JS.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/SRC/Payment/Payment.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/SRC/SRC.md | 2024-11-26 13:22:08 | [376fd4e](https://github.com/EndlessShw/blog/commit/376fd4e732a3d8c49666a96f709d07a0df4b3ff6) | 在现有头部补 date |
| Network_Security/SRC/Unauthorize/Unauthorize.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Chapter2_Easy_Cloudantivirus/Chapter2_Easy_Cloudantivirus.md | 2024-01-13 11:11:18 | [81272bd](https://github.com/EndlessShw/blog/commit/81272bd71079b633ac60fd471fdfba2af62f68f2) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Chapter3_Medium_Chronos/Chapter3_Medium_Chronos.md | 2024-01-20 11:36:05 | [14c79e1](https://github.com/EndlessShw/blog/commit/14c79e11ae3b317c31265e6666022ed34ac9ecb7) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Chapter4_Medium_AdmX_New/Chapter4_Medium_AdmX_New.md | 2024-01-23 15:53:21 | [fc78c49](https://github.com/EndlessShw/blog/commit/fc78c4903856a0aee580f31d2aef89320b5faae8) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Chapter5_Hard_Socnet2/Hard_Socnet2.md | 2024-01-29 11:30:41 | [eec4a02](https://github.com/EndlessShw/blog/commit/eec4a0262a273d81f445aa2399319368be0cca94) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Chapter6_Easy_EvilBox/Easy_EvilBox.md | 2024-02-02 14:26:25 | [3986c3c](https://github.com/EndlessShw/blog/commit/3986c3c1dc1d1a92558ed7c28bdf930404d18588) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Chapter7_Medium_Hacker_Kid/Medium_Hacker_Kid.md | 2024-04-05 13:31:22 | [e8d29b8](https://github.com/EndlessShw/blog/commit/e8d29b8f4d6745a79aa5524116c5d60d17232d58) | 在现有头部补 date |
| Network_Security/Vulnhub_Journey/Conclusion1_Chapter1~5/Conclusion1.md | 2024-01-29 14:26:05 | [14c0be6](https://github.com/EndlessShw/blog/commit/14c0be69b04947b84274d157122df569300c8a79) | 在现有头部补 date |
| Network_Security/Web/File_Include/文件包含漏洞.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/Framework/ThinkPHP/ThinkPHP.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/Web/Java_Security/JWT/JWT.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/Java_Security/Jackson/Serialization_Jackson.md | 2024-11-01 11:36:41 | [4e8019e](https://github.com/EndlessShw/blog/commit/4e8019e3868c5a83a99fc837a6ae9dc1aafc073a) | 在现有头部补 date |
| Network_Security/Web/Java_Security/Jenkins/Jenkins.md | 2025-02-18 09:18:17 | [a15ec23](https://github.com/EndlessShw/blog/commit/a15ec230858a68118cb43f07736fe896a3998eca) | 在现有头部补 date |
| Network_Security/Web/Java_Security/Memory-Trojan-Java/Memory-Trojan-Agent.md | 2025-02-18 09:18:17 | [a15ec23](https://github.com/EndlessShw/blog/commit/a15ec230858a68118cb43f07736fe896a3998eca) | 在现有头部补 date |
| Network_Security/Web/Java_Security/Memory-Trojan-Java/Memory-Trojan-Java.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Network_Security/Web/Java_Security/Misc/Java_Misc.md | 2024-11-01 11:36:41 | [4e8019e](https://github.com/EndlessShw/blog/commit/4e8019e3868c5a83a99fc837a6ae9dc1aafc073a) | 在现有头部补 date |
| Network_Security/Web/Java_Security/RMI/RMI.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 在现有头部补 date |
| Network_Security/Web/Middleware/Tomcat/Tomcat.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/Middleware/WebLogic/WebLogic.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/Python_Security/AuditHook.md | 2025-05-05 21:59:03 | [472fce8](https://github.com/EndlessShw/blog/commit/472fce823e84f5639fdd1aa98d90860faca5ba3b) | 在现有头部补 date |
| Network_Security/Web/RCE/RCE-Java/RCE-Java.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/SSRF/SSRF-Java.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/SSRF/SSRF-PHP.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/SSRF/SSRF.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 在现有头部补 date |
| Network_Security/Web/SSTI/Python/SSTI-Python.md | 2024-05-30 06:57:27 | [d0a5b1c](https://github.com/EndlessShw/blog/commit/d0a5b1ceaaa3ccd0337d091a4c220c6c72233225) | 在现有头部补 date |
| Network_Security/Web/XSS/XSS.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/Web/XXE/XXE.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Network_Security/渗透思路.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| Projects/SpringBoot + Vue 博客系统/SGBlog/笔记/项目实战-前后端分离博客系统.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| Projects/SpringBoot + Vue 博客系统/项目实战笔记.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SSM/Spring/Spring.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| SSM/SpringMVC/SpringMVC.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| SSM/SpringMVC/SpringMVC笔记/SpringMVC-01.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SSM/SpringMVC/SpringMVC笔记/SpringMVC-02.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SSM/SpringMVC/SpringMVC笔记/SpringMVC-03.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SSM/mybatis/mybatis.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot-Node.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot-基础入门.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot-常见场景.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot笔记/SpringBoot笔记（1） - 基本核心内容.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot笔记/SpringBoot笔记（2） - Git 版本控制.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot笔记/SpringBoot笔记（三）.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot笔记/SpringBoot笔记（五）.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringBoot/SpringBoot笔记/SpringBoot笔记（四）.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| SpringSecurity/SpringSecurity/SpringSecurity-从入门到精通-三更草堂.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| Vue/Vue.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| 其他/slay of spire/战士.md | 2024-01-04 20:24:53 | [1d7367b](https://github.com/EndlessShw/blog/commit/1d7367bd7523d6bb3d2f13fb513ca542a6ed231e) | 添加仅含 date 的头部 |
| 其他/穿搭/男士穿搭.md | 2025-02-18 09:18:17 | [a15ec23](https://github.com/EndlessShw/blog/commit/a15ec230858a68118cb43f07736fe896a3998eca) | 在现有头部补 date |
| 寒假英语班/单词与句型整理.md | 2024-04-30 13:53:33 | [67e1283](https://github.com/EndlessShw/blog/commit/67e12839d1e4174c722683c26caf36cbc2d4e78e) | 添加仅含 date 的头部 |
| 建议使用WizTree查看c盘目录，删除文件以释放空间。.md | 2024-12-13 22:07:48 | [1be8370](https://github.com/EndlessShw/blog/commit/1be8370d856423104c661abf9174aa1cf1651b6d) | 添加仅含 date 的头部 |
| 方班/方班.md | 2024-09-24 17:57:32 | [7ee43b2](https://github.com/EndlessShw/blog/commit/7ee43b23e718ca372311742d56c8a9eeb10e3026) | 在现有头部补 date |
| 记笔记要点.md | 2024-12-13 22:07:48 | [1be8370](https://github.com/EndlessShw/blog/commit/1be8370d856423104c661abf9174aa1cf1651b6d) | 添加仅含 date 的头部 |

## 已有 date、原样保留的 43 个文件

- source/_posts/Algorithm/算法汇总/Java.md
- source/_posts/Android/AndroidP7_Service/服务.md
- source/_posts/Android/Android_RecyclerView/RecyclerView.md
- source/_posts/Blog/博客搭建记录.md
- source/_posts/Golang/Bugs/Goland.md
- source/_posts/Golang/GeeCache/GeeCache.md
- source/_posts/Golang/KamaCache/缓存系统.md
- source/_posts/Golang/TelerWaf/TelerWaf.md
- source/_posts/HTML_CSS_JS_JQuery/HTML5/HTML.md
- source/_posts/HTML_CSS_JS_JQuery/JQuery/JQuery.md
- source/_posts/HTML_CSS_JS_JQuery/JavaScript/JavaScript.md
- source/_posts/Network_Security/Intranet/Connection/Connection.md
- source/_posts/Network_Security/Intranet/Kerberos/Kerberos.md
- source/_posts/Network_Security/Misc/Encode/Encode.md
- source/_posts/Network_Security/Misc/Linux/Linux.md
- source/_posts/Network_Security/Misc/Unknown/Unknown.md
- source/_posts/Network_Security/Pwn/Pwn.md
- source/_posts/Network_Security/SRC/EduSRC/EduSRC.md
- source/_posts/Network_Security/Vulnhub_Journey/Chapter1_Medium_Socnet/Chapter1_Medium_Socnet.md
- source/_posts/Network_Security/Web/CVE/CVE-2024-38816/CVE-2024-38816.md
- source/_posts/Network_Security/Web/Java_Security/Fastjson/Serialization-fastjson.md
- source/_posts/Network_Security/Web/Java_Security/Gadgets/Gadgets1.md
- source/_posts/Network_Security/Web/Java_Security/Gadgets/Gadgets2.md
- source/_posts/Network_Security/Web/Java_Security/Hessian/Hessian.md
- source/_posts/Network_Security/Web/Java_Security/JDBC/JDBC.md
- source/_posts/Network_Security/Web/Java_Security/JNDI-Injection/JNDI-Injection.md
- source/_posts/Network_Security/Web/Java_Security/Memory-Trojan-Java/Agent.md
- source/_posts/Network_Security/Web/Java_Security/Memory-Trojan-Java/Memory-Trojan-Servlet.md
- source/_posts/Network_Security/Web/Java_Security/Memory-Trojan-Java/Memory-Trojan-Spring.md
- source/_posts/Network_Security/Web/Python_Security/Python.md
- source/_posts/Network_Security/Web/SQL_Injection/SQL注入.md
- source/_posts/Network_Security/Web/SSI/SSI.md
- source/_posts/Network_Security/Web/Serialization_Vulnerable/Serialization-Java.md
- source/_posts/Network_Security/Web/Serialization_Vulnerable/Serialization-PHP.md
- source/_posts/Network_Security/Web/Upload_WebShell/文件上传漏洞.md
- source/_posts/Network_Security/wp/TSCTF_J.md
- source/_posts/Network_Security/wp/鹏程杯线下.md
- source/_posts/Network_Security/应急响应/应急响应.md
- source/_posts/PHP/PHP.md
- source/_posts/SourceCode_Learning/ysoserial.md
- source/_posts/Working_Experience/NSFocus.md
- source/_posts/cpp/cpp.md
- source/_posts/年终总结/2024.md

## 追溯与复核说明

候选通过只读 git log --follow 获取，并与此前独立核查的 mybatis、网络编程、北邮密码学面试和 Memory-Trojan-Agent 样本交叉核对。当前所有 81 个缺失日期文件均有历史来源，无需使用文件系统时间或当前时间兜底。

同一次批量导入的多篇文章可能取得相同日期；这是已选首次入库规则的结果，不代表算法恢复了它们各自原始写作日期。
