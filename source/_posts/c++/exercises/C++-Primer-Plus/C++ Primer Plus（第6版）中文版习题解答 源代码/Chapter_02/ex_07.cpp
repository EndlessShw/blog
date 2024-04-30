/*第二章：编程练习7 */
#include <iostream>
using namespace std;
/* 预编译指令*/

void format_print(int hour,int minute);
/* 格式化输出函数声明 */
int main() 
{
    float hours, minutes;
    /* 定义float类型变量，用于存储时间数值*/
    cout<<"Enter the number of hours: ";
    cin>>hours;
    cout<<"Enter the number of minutes: ";
    cin>>minutes;
    /* 通过标准化输入，读取数据，并存储入对应变量 */
    format_print(hours,minutes);
    /* 函数调用，将会打印格式化数据，函数无返回值 。*/
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束的花括号 */

void format_print(int hour,int minute)
{
    cout<<"Time: "<<hour<<":"<<minute<<endl;
}
/* 函数的定义，无返回值函数可以不使用return语句，这样
 * 函数会运行到最后一句，然后自动返回。 */

