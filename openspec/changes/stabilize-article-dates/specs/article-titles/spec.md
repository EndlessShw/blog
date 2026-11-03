# Spec Delta

## Purpose

为当前博客中缺失文章标题的页面补齐明确的展示名称，优先利用正文已有标题，在没有正文标题时使用用户指定的固定占位。补齐操作应保持既有文章标题、发布时间、正文和 URL，避免把章节名误作整篇文章名称或改动用户原有内容。

## ADDED Requirements

### Requirement: 仅补齐缺失或空文章标题

系统 SHALL 将缺失、null 或空白 title 视为需要补齐的标题。现有非空 title MUST 保持原值；本次写入范围 SHALL 限于根仓库跟踪的 source/_posts/ Markdown，不修改额外工程说明或其他目录。

#### Scenario: 当前文章标题迁移
- **WHEN** 对基线提交 3167153 的 124 篇根仓库文章执行标题补齐
- **THEN** 仅处理 46 个缺失 title 和 3 个空 title，其余 75 个非空标题保留

### Requirement: 从正文提取可用标题

系统 SHALL 从 Markdown 正文的实际非空标题中提取展示文本，忽略代码示例和空标题，不把文件名或普通首段自动当作正文标题。除用户单独指定的文章外，本次 SHALL 使用第一个实际正文标题，保留其文字内容而去除标题及行内格式标记。

#### Scenario: 正文存在明确标题
- **WHEN** 内容提供者.md 缺少 title，正文首个标题为“内容提供者”
- **THEN** 写入 title“内容提供者”，正文标题保持原样

#### Scenario: 示例代码或空标题
- **WHEN** 正文代码块中出现井号标题文字，或引用块中只有空标题标记
- **THEN** 不将其作为文章标题候选

### Requirement: 使用用户明确确认的整篇标题

系统 SHALL 对以下四篇文章采用用户确认的标题：Servlet-JSP-课堂笔记.md 为“Servlet 与 JSP 课堂笔记”；Android_NFC.md 为“Android NFC：NDEF 数据操作与过滤机制”；项目实战-前后端分离博客系统.md 为“SpringBoot + Vue 前后端分离博客系统实战”；SpringBoot.md 为“SpringBoot 快速入门”。

#### Scenario: 首个章节名不代表整篇内容
- **WHEN** Servlet-JSP-课堂笔记.md 的首个正文标题为“关于直播”
- **THEN** 使用已确认的“Servlet 与 JSP 课堂笔记”，不自动以开场章节名替代

### Requirement: 无正文标题时使用固定占位

系统 SHALL 在没有可用正文标题时填入精确值“标题 TODO”，不擅自根据文件名、普通段落或模型推测文章名。

#### Scenario: 空正文或仅有普通文字
- **WHEN** 领卷联盟.md、CSS.md 或建议使用WizTree查看c盘目录，删除文件以释放空间。.md 没有可用 Markdown 标题
- **THEN** 分别填写“标题 TODO”，不删除空文章或改写正文

### Requirement: 补标题保持正文日期和 URL

系统 SHALL 只新增或替换目标 YAML title，正确引用字符串，并保持其余元数据、正文、编码和换行字节。操作 MUST 不改文件路径、slug、permalink 或发布时间，重复执行 MUST 不覆盖已有非空标题。

#### Scenario: 多个占位标题相同
- **WHEN** 三篇文章均填入“标题 TODO”且文件路径、slug 和 permalink 配置未变
- **THEN** 保持原文章 URL，不因显示标题相同而主动改名或重新分配 URL

#### Scenario: 标题含特殊字符
- **WHEN** 标题含冒号、引号或其他 YAML 特殊字符
- **THEN** 写入后解析得到完整字符串，不产生额外字段，正文和 date 不变
