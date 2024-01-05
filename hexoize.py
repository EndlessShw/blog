import regex as re
import os
import argparse


def rename(rootPath):
    # print(rootPath)
    for root, dirs, files in os.walk(rootPath, topdown=False):
        for dirName in dirs:
            # 处理修改文件夹名，将 xxx.assets 改成 xxx
            renameFolder(dirName, root)
        for fileName in files:
            # 处理修改 .md 文件中的图片路径
            if fileName.endswith(r".md"):
                alterMarkdown(os.path.join(root, fileName))


def renameFolder(dirName, root):
    """
    删除所有子文件夹下以 .assets 结尾的文件夹的 .assets 后缀
    :param dirName: 子文件夹的名字
    :param root: 子文件夹的绝对路径，不含 dirName
    :return:
    """
    dirNewName = re.sub(r"\.assets$", "", dirName)
    os.rename(os.path.join(root, dirName), os.path.join(root, dirNewName))
    # print("dir is " + os.path.join(root, dirNewName))


def alterMarkdown(filePath):
    """
    修改所有 markdown 文件中图片的路径
    :param filePath:
    :return:
    """
    # print(filePath)
    allContent = ""
    with open(filePath, "r", encoding="utf-8") as openFile:
        allContent = re.sub(r"(?<=\!\[.*\]\().*?\/", "", openFile.read())
    with open(filePath, "w", encoding="utf-8") as writeFile:
        writeFile.write(allContent)


def main():
    parser = argparse.ArgumentParser()
    parser.description = '请输入要转化的文件的根路径'
    parser.add_argument("-p", "--rootPath", help="根路径名", dest="rootPath", type=str, default="")
    args = parser.parse_args()
    rootPath = args.rootPath
    if rootPath == "":
        rootPath = input("请输入路径:")
    rename(rootPath)


if __name__ == '__main__':
    main()
