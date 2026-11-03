# 文章发布时间与更新时间

## 当前状态

2026-11-03：81 篇缺失发布时间已随 `3167153` 上线；49 篇缺失或空标题已随 `4193cf0` 上线，用户已分别确认。动态更新时间已实现；2026-11-04 用户授权通过 GitHub → Vercel 发布。本次功能不包含用户本地依赖升级，部署状态以对应提交的 Vercel 记录为准。

本轮不为配套工程添加 `updated_assets`：用户选择只自动追踪正文引用的本地附件。显式声明能力已经实现，留待以后按需使用。没有修改文章正文、已有标题或 date，也没有修改依赖源码。

## 时间含义

- `date`：固定发布时间，已有值始终保留。缺失时以可追溯的首次入库提交者时间补齐；首次入库不是已证实的真实首发。
- `updated`：文章及其关联附件的有效变更提交者时间中，最近的时刻。编辑、push、部署及文件系统时间均不参与。
- 页面以 `Asia/Shanghai` 展示。首页与归档按 `date` 排序；Fluid 文章开头在两个时间不同时显示更新时间，相同时隐藏该提示。

正文、排版、标签、已有非空标题及其他非时间元数据变化算更新。仅补齐缺失/空 title、维护顶层 date/updated、转换 CRLF/LF 或内容不变的移动/重命名不算更新；“标题 TODO”改成正式标题属于已有标题修改。相同提交若还改了正文或附件，仍算更新。

比较 YAML 时按字段值及结构判断，排除时间字段；正文保留除 CRLF/LF 之外的空白。二进制按内容判断。合并结果已存在于某个父提交时沿来源追溯，冲突解决产生的新内容算更新。Git 无法确认的重命名身份会诊断，不用文件名猜测。

## 日常操作

修改文章或已关联附件后正常 commit、push 即可。构建自动计算更新时间，不需要手填 updated、不依赖本地 Git hook，也不会将派生 updated 写回 Markdown。已有静态 updated 会被构建结果覆盖。

本地未提交的正文可正常预览，但更新时间和附件归属取 HEAD 中已提交的版本；新文章尚未提交时明确报错，请先提交。已经 git add 但未 commit 也不构成可用历史。

```powershell
# 默认只读，输出时间、来源提交、附件、诊断及配套工程候选。
node tools/article-timestamps.js

# 保存完整预览；输出只是检查报告，不是构建时读取的日期数据库。
node tools/article-timestamps.js --output article-timestamps-preview.log

# 指定文章（中文/空格路径必须正确引用）。
node tools/article-timestamps.js --file "source/_posts/SSM/mybatis/mybatis.md"

# 只在确有缺失 date 时显式写入，保留已有 date；先完成全部预检再写入。
node tools/article-timestamps.js --write-missing-dates

# 需要时允许预览工具补历史；默认预览不会联网。
node tools/article-timestamps.js --fetch

npm run build
npm run test:dates
```

旧入口仍可使用 `python update.py -p "文章路径"` 或 `update.bat "文章路径"`；它们转调同一工具，只补缺失 date，不再用 mtime 覆盖日期。批处理以自身所在目录定位脚本，不再写死 D 盘路径。

## 本地附件的边界

自动解析 Markdown 图片、文件链接、引用式链接和 HTML 真实资源属性。跳过代码块、行内代码、HTML pre/code/script/style 示例、外部协议及纯锚点，不递归分析 Java import、XML 或远程项目。

- 普通文件链接相对于文章所在目录解析。
- 图片支持当前 Hexo 文章资源目录、`文章名/图片.png`、裸图片名和站点根 `/images/图片.png`，也处理中文、URL 编码、查询串、片段及 Windows 反斜线。
- 只追踪根仓库 Git 历史，越出仓库、未跟踪或失效路径逐项报告，不按同名文件猜测替代路径。失效旧引用本身不阻断全站。
- 被删除但有历史的附件会计入删除提交。共享附件影响所有引用它的文章。文章自引用或归属目录包含自身时，不会绕过日期/标题维护例外。
- 子模块只比较父仓库记录的 gitlink 版本，不读取子模块工作区；对子模块内部文件的引用归到 gitlink，删除事件同样参与。

没有正文链接的工程可以以后明确声明；本轮没有自动写入任何声明：

```yaml
updated_assets:
  - code/mybatis/
  - examples/Main.java
```

路径相对于 Markdown 所在目录，目录必须以 `/` 结尾。目录内全部受版本控制文件的增加、修改和删除都算，包括已跟踪的 class/jar；不按扩展名排除，也不会把未归属的同级文件混算进来。声明自身属于非时间元数据，修改声明算一次文章更新。

根仓库跟踪的 `source/_posts/**/*.md` 是本次处理范围。当前 124 篇；8 个被忽略的工程 HELP.md 和 1 个子模块 README.md 不写日期、不纳入时间计算、不改变渲染范围，只在构建日志汇总为范围外记录。

## 实现位置与构建入口

- `lib/article-timestamps/git.js`：Git 历史、逐父提交差异、重命名追溯、批量 blob 读取和单次构建缓存。
- `content.js`：YAML/正文比较、二进制比较、日期解析和保留原文件格式的缺失 date 插入。
- `assets.js`：语法解析附件及归属诊断。
- `index.js`：汇总检查、迁移和 Hexo 模型适配。
- `scripts/article-timestamps.js`：Hexo `before_generate` 薄扩展，优先级 5。
- `tools/prepare-git-history.js`：构建前确认历史完整，浅克隆时尝试 `git fetch --unshallow --no-tags origin`，不切换 HEAD 或覆盖工作区。

Fluid 的默认优先级 10 过滤器会保存文章列表，因此日期必须在它之前通过 `await post.update({date: Date, updated: Date})` 更新模型。Warehouse 查询返回文档副本，单纯给查询结果赋值不会更新随后生成页面使用的数据。日期以明确瞬时值交给 Hexo 的 Moment 类型处理，避免重复时区转换；每次生成都重新计算，不以 Markdown mtime 为缓存键。

解析器复用已安装 Hexo 包自身声明的 js-yaml、moment-timezone、marked、htmlparser2，通过 Node createRequire 按所属包解析；没有新增安装依赖或修改 node_modules。缺少这些依赖会明确失败。

`package.json` 的 build 先运行历史准备，再执行 hexo generate；`vercel.json` 明确配置 `buildCommand: npm run build`。Vercel 既有日志已确认会执行仓库 build，插件也确认项目为 Hexo、Node 设置 24.x。此次接口未返回自定义 Build/Install Command 或 Root Directory，不能据此声称这些字段的具体值。

完整历史可以离线构建；浅克隆无法补齐、没有 .git 或无有效文章历史时停止生成，不回退到当前时间或文件时间。Hexo 会捕获脚本顶层加载异常，因此核心 require 放在已注册过滤器内，运行期失败能传播；独立历史准备 CLI 同样会硬失败。

推送后应在 Vercel 本次提交的构建日志确认以下两条，再核对文章页面：

```text
[article-timestamps] Git 历史已就绪：<本次提交>
[article-timestamps] 124 篇文章使用 Git 时间；9 个范围外记录保持原处理；HEAD <本次提交>
```

文章数量随后续新增内容变化；9 个范围外记录是本地现状，线上不一定包含被忽略文件。本轮没有自动发布，因此新增入口在 Vercel Linux 构建机上的实际运行仍待推送后核验。

## 预览与已知数据问题

完整当前预览见 `research/2026-11-03-article-updated-preview.json`，便于阅读的逐篇表见同名 `.md`。报告对应 HEAD `4193cf0`；有新提交后应重新生成。

- 124 篇均已有 date，补齐操作再次执行写入 0 个文件。
- 958 条文章内去重后的附件依赖；45 条引用没有根仓库可用历史、1 条空引用，报告保留原路径，不批量修链接。
- `source/_posts/Network_Security/Intranet/Connection/Connection.md` 的 date 为 `2024-10-11 15:02:41 +08:00`，Git 更新时间为 `2024-05-30 06:57:27 +08:00`。按约定只报告，不改写、不钳制；Fluid 因两者不同会显示更新时间。
- mybatis 的 `code/mybatis/` 只作为未链接工程候选列出。用户选择本轮不声明，它暂不参与计算。

## 验证及回退

测试使用 Node 原生测试与独立临时 Git 仓库，覆盖中文/空格、正文空白、时间/标题维护、CRLF、二进制、共享附件、目录删空、纯重命名、合并/冲突、gitlink 更新/删除、新文章暂存状态、自引用、失效引用和浅克隆成功/离线失败。

真实 Hexo/Fluid 集成测试生成 HTML，检查静态 updated 不固定结果、首次时间相同隐藏、仅图片提交后复用缓存仍显示新时间、源文件不回写、首页和归档顺序不变。跨时区进程及改变换行/文件时间验证结果一致。真实仓库另做 clean build、缓存构建与隔离检出核对；结果见预览报告的验证记录。

本地安装版本为 Hexo 8.1.2 / Fluid 1.9.9。用户已有未提交的依赖升级、锁文件调整、README、两篇文章及脏子模块均保留；没有为了本任务一并提交或覆盖它们。线上当前提交的依赖范围与本地安装可能不同，线上新增入口必须在发布后再验收。

需要回退时，仅撤销本次 lib/tools/scripts、配置、build 脚本和旧入口改动；保留已上线的固定 date 和标题。不要用 reset/checkout 整个工作区覆盖已有修改，不需要为了回退重新运行旧版 mtime 脚本。


最终验证：16/16 测试通过；真实 Hexo/Fluid 测试在当前主机时区及 TZ=UTC 均通过。真实仓库 clean build：1385 文件，Files loaded 12 s，生成 1.71 s；缓存构建：0 个文件变化，Files loaded 13 s，生成 734 ms。124 篇 HTML 的 published/modified 元数据及更新时间提示逐篇匹配报告（88 显示、36 隐藏），缓存前后保持一致。隔离克隆同一 HEAD，LF+UTC 与 CRLF+America/Los_Angeles、文件时间改为 2035-01-01 后，124 篇 date/updated/来源提交全部一致。生成和旧入口验证期间，2084 个现存受跟踪文件哈希保持不变。旧 Python 及含空格中文路径的批处理入口均写入 0 个 date。

## 2026-11-04 发布前兼容验证

保留仓库原有依赖和两种锁文件，仅合入 build/preview/test 脚本。以 HEAD 的 package-lock.json 在隔离克隆执行 npm ci --ignore-scripts，实际 Hexo 7.1.1、hexo-renderer-marked 6.2.0 / Marked 4.3.0、Fluid 1.9.7 下 16/16 测试通过，全站构建成功（124 篇文章，1368 个输出文件；此隔离环境不含本地忽略文件或子模块说明）。解析器使用跨版本 Lexer/walkTokens 接口；htmlparser2 从 Hexo 声明的 hexo-util 依赖链解析，不要求博客根目录直接声明 hexo-util。没有为本次发布升级依赖或重写锁文件。

## 2026-11-04 Vercel 浅克隆修正

首次生产构建确认 Vercel 的浅克隆没有 origin，历史预检按设计失败，未替换原有站点。构建入口现读取标准 package.json repository.url；有 origin 时沿用，否则使用显式源仓库 URL，只获取当前 HEAD 对应历史，不切换 HEAD、不添加远程或拉取工作区。已添加无 origin 浅克隆回归场景，仍不允许回退到文件时间。
