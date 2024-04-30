/*第三章：编程练习 1 */
#include <iostream>
using namespace std;
/* 预编译指令*/
const int FOOT_TO_INCH = 12;
/* 定义符号常量，该常量定义后数值不会改变 */

int main() 
{
    int height;
    cout<<"Enter your height in inchs_";
    cin>>height;
    /* 定义变量，并通过标准输入读取用户输入 */
    cout<<endl<<"Your Height convert to "<<height/FOOT_TO_INCH;
    cout<<" foot and "<<height%FOOT_TO_INCH<<" inch height."<<endl;
    /* 打印显示输出，并在输出语句内直接计算转换后数值，并显示 */
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束花括号  */
