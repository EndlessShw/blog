/*第三章：编程练习 4 */
#include <iostream>
using namespace std;
/* 预编译指令*/
const int DAY_TO_HOUR = 24;
const int HOUR_TO_MINUTE = 60;
const int MINUTE_TO_SECOND = 60;

/* 定义符号常量，表示单位转换因子 */
int main()
{
    long long seconds;
    int days, hours, minutes;
    /* 选择合适的数据类型 ，定义变量 */
    cout<<"Enter the number of  seconds:";
    cin>>seconds;
    cout<<seconds <<" seconds = ";
    days = seconds / (DAY_TO_HOUR * HOUR_TO_MINUTE * MINUTE_TO_SECOND);
    seconds = seconds % (DAY_TO_HOUR * HOUR_TO_MINUTE * MINUTE_TO_SECOND);

    hours = seconds / (HOUR_TO_MINUTE * MINUTE_TO_SECOND);
    seconds = seconds %(HOUR_TO_MINUTE * MINUTE_TO_SECOND);
    /* C++语言中运算符优先级问题，可以使用括号确保正确的运算顺序 */
    minutes = seconds / MINUTE_TO_SECOND;
    seconds = seconds % MINUTE_TO_SECOND;
    /* 读取标准输入数据 */
    cout<<days<<" days, "<<hours<<" hours,"<<minutes<< " minutes, "
        <<seconds<<" seconds."<<endl;
    /* 转换数据格式，并打印输出 */
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束花括号  */


