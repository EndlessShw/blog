/*第四章：编程练习 4 */
#include <iostream>
#include <string>
/* 使用string 需要添加string头文件 */
using namespace std;
/* 预编译指令*/
int main()
{
    /*char first_name[SIZE], last_name[SIZE];
    char full_name[SIZE * 2 + 1];
    分别定义姓、名、和全名，注意字符数组的长度。*/
    string first_name, last_name, full_name;
    /* 定义三个字符串变量 */
    cout<<"Enter your first name: ";
    getline(cin, first_name);
    cout<<"Enter your last name: ";
    getline(cin, last_name);
    full_name = last_name + ". "+ first_name;
    /* string可以使用 + 和 = 进行字符串的合并和复制，其中”.”双引号表示字符串 */
    cout<<"Here's the information in a single string: ";
    cout<<full_name<<endl;
    return  0;
}
/* main()函数结束，返回值和花括号 */

