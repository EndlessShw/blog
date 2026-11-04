# AI 周报内容接入

栏目入口为 `/ai-weekly/`，导航中与首页、归档同级。列表按发布时间倒序，每页 10 期。周报不进入普通首页、归档、分类、标签、文章统计或普通文章前后篇，但标题及正文进入全站搜索。

## 添加一期周报

1. 复制 `scaffolds/ai-weekly.md` 为 `source/ai-weekly/<slug>/index.md`，例如 `source/ai-weekly/2026-11-02/index.md`。不要使用 `hexo new ai-weekly`，该命令会把自定义布局文章放进普通文章目录。
2. 由生成周报的对话填写元数据和正文。这里只提供内容接入，不负责 AI 生成、定时任务或自动发布。
3. 运行 `pnpm run build` 验证，使用 `pnpm run server` 本地查看。之后沿用博客现有提交和部署流程。

目录名只能使用小写英文字母、数字和单连字符；一期对应一个目录及一个 `index.md`。目录名决定永久链接，例如 `/ai-weekly/2026-11-02/`，修订标题或正文时保留目录名。

## 元数据

```yaml
---
layout: ai-weekly
title: "AI 周报：本期主题"
published_at: "2026-11-04T12:00:00+08:00"
summary: "本期纯文本摘要，可省略。"
---
```

- `layout` 必须为 `ai-weekly`。
- `title` 必填，表示整期标题。
- `published_at` 必填，使用带时区、含秒的 ISO 8601 字符串并加引号；北京时间使用 `+08:00`。它表示首次发布时间，决定排序；修订时保留原值。不要用文件创建/修改时间，也不要另外填写 `date`、`updated`。
- `summary` 可选，仅纯文本；省略后列表只展示标题、日期和 AI 生成标识。
- 不填写 `permalink`，保持链接由目录确定。
- 不需要填写 `categories`、`tags`；即使填写也不会创建普通文章分类或标签。
- 需要从全站搜索排除某一期时，可填写 `indexing: false`，其详情和专栏列表仍然公开。

错误路径、布局、标题、日期或摘要会中断构建，并提示出错文件，避免静默丢失内容或采用文件时间。

## 图片、草稿与修订

图片放在该期目录下，例如 `cover.png`，正文使用 `![说明](./cover.png)`。正文支持现有 Markdown 和 Fluid 的代码高亮等阅读功能。

`source/ai-weekly/` 内的合规周报都会随正常构建发布；未来的 `published_at` 不会提供预约发布能力。未准备好的内容留在 `source` 外，不依赖 `draft: true` 隐藏普通 Page。

删除一期时删除对应目录，按现有部署流程重新构建。大规模清理历史输出时使用 `pnpm run clean` 后再构建。

栏目没有报告时展示空状态；模板保存在 `scaffolds/`，不会作为真实周报发布。

## 回归检查

```sh
node --test test/ai-weekly/hexo.test.js
pnpm run test:dates
pnpm run build
```
