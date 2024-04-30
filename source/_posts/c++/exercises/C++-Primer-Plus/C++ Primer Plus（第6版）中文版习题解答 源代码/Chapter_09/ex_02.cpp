/*第九章：编程练习 2 */
//static.cpp -- using a static local variable
#include <iostream>
#include <string>
/* 添加相应头文件 */
// constants

// function prototype
void strcount(const std::string str);

int main()
{
    using namespace std;
    string input;
    /* 替换原字符数组形式，使用string类型 */
    char next;

    cout << "Enter a line:\n";
    getline(cin,input);
    /* string从cin读取输入，需要使用getline()函数 */
    while (input != "")
    /* string字符串判断为空，可以直接使用比较运算符 */
    {
        strcount(input);
        cout << "Enter next line (empty line to quit):\n";
        getline(cin,input);
    }
    cout << "Bye\n";
    return 0;
}

void strcount(const std::string str)
{
    using namespace std;
    static int total = 0;        // static local variable
    int count = 0;               // automatic local variable

    cout << "\"" << str <<"\" contains ";
    /* 可以使用字符串末尾的空字符判断结束
     * while(str[count])               // go to end of string
     * count++;
     * 但是对于string判断其长度可以直接使用string的函数。
     * */
    count  = str.length();
    total += count;
    cout << count << " characters\n";
    cout << total << " characters total\n";
}
