import regex as re
import os
import argparse
from datetime import datetime


def update(filePath):
    # 打开文件
    YAMLContent = ""
    allContent = ""
    with open(filePath, 'r', encoding="utf-8") as openFile:
        allContent = openFile.read()
        # 定位文件的 YAML 部分
        YAMLContent = re.search(r"(?<=---).*?(?=---)", allContent, re.S).group(0)
        # 获取文件的修改日期
        updateTime = datetime.fromtimestamp(os.path.getmtime(filePath)).strftime("%Y-%m-%d %H:%M:%S")
        # 如果不包含 date，就插入 date
        if YAMLContent.find("date") == -1 :
            YAMLContent += "date: " + updateTime
            YAMLContent += "\n"
        # 如果包含 date，就修改 date 后面的内容
        else:
            # 获取原先文件内容中的 date
            oldDate = re.search(r"(?<=date: ).*", YAMLContent).group(0)
            # 如果发生了修改，则修改时间不同，那么 date 的内容就要替换
            # print(oldDate[:-4])
            # print(updateTime[:-4])
            # 实际上 oldDate 和 updateTime 有时间误差，因此控制在 10 分钟内
            if oldDate[:-4] != updateTime[:-4]:
                YAMLContent = re.sub(r"(?<=date: ).*", updateTime, YAMLContent)
            # 如果没有发生修改，就啥也不做
            else:
                pass
        allContent = re.sub(r"(?<=---).*?(?=---)", YAMLContent, allContent, 1, re.S)
    with open(filePath, 'w', encoding="utf-8") as writeFile:
        writeFile.write(allContent)
    pass


def rename(rootPath):
    # print(rootPath)
    for root, dirs, files in os.walk(rootPath, topdown=False):
        for dirName in dirs:
            # 处理修改文件夹名，将 xxx.assets 改成 xxx
            renameFolder(dirName, root)
        for fileName in files:
            # 处理修改 .md 文件中的图片路径和时间
            if fileName.endswith(r".md"):
                alterMarkdown(os.path.join(root, fileName))
                update(os.path.join(root, fileName))


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
