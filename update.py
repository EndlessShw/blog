# -*- coding: utf-8 -*-
"""兼容旧调用：只补缺失的发布时间，更新时间由 Hexo 构建时计算。"""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description="仅为已提交文章补齐缺失 date，保留已有日期")
    parser.add_argument("-p", "--rootPath", default="")
    args = parser.parse_args()
    article = args.rootPath or input("请输入文章路径: ")
    root = Path(__file__).resolve().parent
    print("已有 date 不会改写；更新时间由 Git 历史在 Hexo 生成时自动计算。")
    return subprocess.run(
        ["node", str(root / "tools" / "article-timestamps.js"), "--file", str(Path(article).resolve()), "--write-missing-dates"],
        cwd=root, check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
