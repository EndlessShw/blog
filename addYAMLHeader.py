# -*- encoding: utf-8 -*-
"""
@File    : addYAMLHeader.py
@Time    : 2024/1/3 17:52
@Author  : EndlessShw
@Email   : 1502309758@qq.com
@Software: PyCharm
"""
import regex as re
import os
import argparse


def addHeader(filename, filePath):
    """
    添加头部
    :param filePath: 文件的绝对路径
    :return:
    """
    allContent = "---\n"
    allContent += "title: "
    allContent += re.sub(r"\.md", "", filename)
    allContent += "\n"
    allContent += "---\n"
    f = open(filePath, encoding="utf-8")
    allContent += f.read()
    f.close()
    with open(filePath, "w", encoding="utf-8") as writeFile:
        writeFile.write(allContent)
    pass


def addYAMLHeader(rootPath):
    """
    为每个 md 文件头部添加 YAML 文件头
    :param rootPath:
    :return:
    """
    for root, dirs, files in os.walk(rootPath, topdown=False):
        for fileName in files:
            # 为每个 markdown 文件添加 YAML 头部
            if fileName.endswith(r".md"):
                addHeader(fileName, os.path.join(root, fileName))

def main():
    parser = argparse.ArgumentParser()
    parser.description = '请输入要添加头部的文件的根路径'
    parser.add_argument("-p", "--rootPath", help="根路径名", dest="rootPath", type=str, default="")
    args = parser.parse_args()
    rootPath = args.rootPath
    if rootPath == "":
        rootPath = input("请输入路径:")
    addYAMLHeader(rootPath)


if __name__ == '__main__':
    main()
