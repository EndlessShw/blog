/*第二章：编程练习4 */
#include <iostream>
using namespace std;
/* 预编译指令*/

int main() 
{
    int years;
    /* 定义变量存储读取的数据，可以使用整型数据 */
    cout<<"Enter your age: ";
    cin>>years;
    /* 通过cin读取数据，保存至years 内 */
    cout<<"You are "<<years<<" old, or ";
    cout<<12*years<<" month old."<<endl;
    /* 输出数据，并在输出语句内通过12*years直接计算月份并输出 */
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束的花括号 */
