/*第四章：编程练习 3 */
#include <iostream>
#include <cstring>
/* 使用字符数组的处理函数需要添加cstring头文件 */
using namespace std;
/* 预编译指令*/
const int SIZE = 20;
/* 使用常量表示字符数组长度 */
int main()
{
    char first_name[SIZE], last_name[SIZE];
    char full_name[SIZE*2];
    /* 分别定义姓、名、和全名，注意字符数组的长度。*/
    cout<<"Enter your first name: ";
    cin.getline(first_name, SIZE);
    cout<<"Enter your last name: ";
    cin.getline(last_name, SIZE);
    /* 读取用户输入 */
    strcpy(full_name,last_name);
    strcat(full_name,", ");
    strcat(full_name,first_name);
    /* 通过strcpy()函数和strcat()函数，将两个字符串复制和组合 */
    cout<<"Here's the information in a single string: ";
    cout<<full_name<<endl;
    return  0;
}
/* main()函数结束，返回值和花括号 */
