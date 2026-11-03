# 现有文章日期核查

调查日期：2026-11-03。本次仅作只读核查与需求记录，未写入文章日期，未运行 Hexo，未修改数据库或部署。

## 已确认的迁移规则

- 用户再次确认：已有 date 全部保留；缺失 date 用追溯重命名后的首次可追溯 Git 入库时间补齐。
- 即使发现历史中曾有不同的 date，本轮也不恢复旧值，不把缺失日期改为优先使用历史 date。
- 用户确认：仅维护顶层 date、updated 不算内容更新，日期整理提交不能让旧文章的内容更新时间全部刷新。
- 补齐值是推定发布时间，不承诺恢复真实首发时间。
- 本轮范围已确认：仅处理 source/_posts/ 下根仓库跟踪的 124 个 Markdown；额外 9 个工程说明单列，不写入日期，不修改其他目录或现有渲染规则。
- 完整补齐候选见 [81 个缺失日期文件预览](2026-11-03-article-date-fill-preview.md)。其中 35 个补现有头部字段、46 个新增仅含 date 的头部；已有 date 的 43 个文件原样保留。
- 按所选规则，32 个候选为 2024-01-04 20:24:53、27 个为 2024-04-30 13:53:33，合计 59/81 个集中在两次批量入库时刻。这是首次入库代理值的结果，不代表同日完成写作。

## 当前集合与日期统计

| 集合 | 数量 | 已有有效 date | 缺少 date | 已填 updated |
| --- | ---: | ---: | ---: | ---: |
| 根仓库跟踪的 Markdown | 124 | 43 | 81 | 0 |
| 工作区实际 Markdown | 133 | 43 | 90 | 0 |
| db.json Post 记录 | 133 | — | — | — |

根仓库 81 个缺日期文件中，35 个有 front matter 但没有 date，46 个没有 front matter。按当前 Hexo 的换行/BOM 处理方式解析，没有发现 YAML 解析错误或无效日期。124 个根仓库跟踪文件均有可追溯 Git 历史。

工作区 Markdown 与 db.json Post 的路径集合完全一致，差异不是删除文件留下的旧缓存。多出的 9 个是 8 个被各自工程 .gitignore 忽略的 HELP.md，以及 1 个由子模块跟踪的 memShell/README.md。

## 实际文章识别规则

`_config.yml:24` 配置 source_dir 为 source；未配置 resources 作为源目录。当前文章源路径是 source/_posts/。

当前安装的 Hexo 处理器检查源目录内的 _posts/ 前缀、非隐藏路径、是否可渲染及 skip_render。post_asset_folder 为 true、new_post_name 为 :title.md 时，可渲染文章扩展名限制为 .md；没有以“是否是工程说明”“是否受 Git 跟踪”或“是否含 front matter”作为文章资格条件。

因此，放在 source/_posts/ 工程目录里的 HELP.md 和子模块 README.md 也可能进入本地文章集合。本次只在讨论日期迁移范围，不自行改变它们的渲染行为。

## 代表性 Git 追溯结果

以下时间均为北京时间。首次 Git 时间是入库代理值，最近文件提交不是已实现的有效内容更新时间计算，不能混用。

| 文件（相对 source/_posts/） | 当前 date | 首次可追溯入库时间 | 首次提交 |
| --- | --- | --- | --- |
| HTML_CSS_JS_JQuery/HTML5/HTML.md | 2024-05-01 13:55:49 | 2024-01-04 20:24:53 | 1d7367b |
| PHP/PHP.md | 2024-09-24 17:18:52 | 2024-04-30 13:53:33 | 67e1283 |
| Golang/Bugs/Goland.md | 2025-08-21 22:40:20 | 2025-08-21 22:41:43 | d154390 |
| SSM/mybatis/mybatis.md | 缺失 | 2024-01-04 20:24:53 | 1d7367b |
| Android/AndroidP9_InternetProgram/网络编程.md | 缺失 | 2024-01-04 20:24:53 | 1d7367b |
| Cryptography/北邮密码学面试.md | 缺失 | 2024-04-30 13:53:33 | 67e1283 |
| Network_Security/Web/Java_Security/Memory-Trojan-Java/Memory-Trojan-Agent.md | 缺失 | 2025-02-18 09:18:17 | a15ec23 |

已沿重命名追溯，例如网络编程.md 的历史名称为 Internet_Program.md。43 个已有日期中，有 19 个早于首次可追溯入库时间；这可能是正常的延后导入，不能认定日期错误。

## 历史日期变化证据及本轮处理边界

针对当前路径匹配历史补丁，至少 14 个已有 date 的文件曾发生旧值到新值替换，至少 39 个缺 date 的文件曾明确删除日期。这两个下界未合并全部历史旧路径，不能称为完整跨重命名总数。

- PHP/PHP.md：d0a5b1c 将 2024-05-06 11:04:22 改为 2024-05-16 16:26:44，7ee43b2 又改为当前 2024-09-24 17:18:52。
- HTML_CSS_JS_JQuery/HTML5/HTML.md：c4dfb74 将 2024-02-02 14:25:18 改为 2024-04-05 13:32:28，67e1283 删除日期，802fe39 重新添加当前日期。
- SSM/mybatis/mybatis.md：67e1283 删除了 date: 2024-04-05 13:32:30，当前缺失。
- Network_Security/Web/Java_Security/Memory-Trojan-Java/Memory-Trojan-Agent.md：472fce8 删除了 date: 2025-02-17 19:40:32，当前缺失。

这些证据不能证明改写由 update.py 执行，也不能证明更早值必然正确。用户看过此类证据后明确选择继续保留现值、缺失使用首次入库代理值，因此本轮不进行历史日期恢复。

## 需单独列出的工程说明

8 个 HELP.md 分别位于以下工程目录，均被各自 .gitignore 的 HELP.md 规则排除：

- Network_Security/Web/CVE/CVE-2024-38816/range/CVE-2024-38816/
- Network_Security/Web/Java_Security/Fastjson/range/Fastjson-Principle/
- Network_Security/Web/Java_Security/Jackson/JacksonRange/
- Network_Security/Web/Java_Security/JDBC/jdbc_range/
- Network_Security/Web/Java_Security/Memory-Trojan-Java/range/springApi/
- Network_Security/Web/Java_Security/RMI/range/RMI/
- Network_Security/Web/RCE/RCE-Java/range/serialization/
- Network_Security/Web/RCE/RCE-Java/range/SpEL-Rce/

第 9 个为 Network_Security/Web/Java_Security/Memory-Trojan-Java/range/memShell/README.md，由子模块跟踪，不是根仓库直接跟踪的文章。
