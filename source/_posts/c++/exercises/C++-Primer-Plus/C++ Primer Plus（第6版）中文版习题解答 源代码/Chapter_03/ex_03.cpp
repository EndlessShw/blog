/*第三章：编程练习 3
 * */
#include <iostream>
using namespace std;
/* 预编译指令*/
const int DEGREE_TO_MINUTE = 60;
const int MINUTE_TO_SECOND = 60;
/* 定义符号常量，表示单位转换因子 */

int main()
{
    int degree, minute, second;
    float degree_style;
    /* 定义数据变量，选择合适的数据类型表示角度 */
    cout<<"Enter a latitude in degrees, minutes, and seconds:"<<endl;
    cout<<"First, enter the degree:";
    cin>>degree;
    cout<<"Next, enter the minutes of arc:";
    cin>>minute;
    cout<<"Finally, enter the seconds of arc:";
    cin>>second;
    /* 读取用户的输入数据 */
    degree_style = degree + float(minute) / DEGREE_TO_MINUTE +
                   float(second)/(MINUTE_TO_SECOND * DEGREE_TO_MINUTE);
    /* C++语言中运算符优先级，可以使用括号确保正确的运算顺序 */
    cout<<degree<<" degrees,  "<<minute<<" minutes, "
        <<second<<" seconds = "<<degree_style <<" degrees"<<endl;
    /* 转换数据格式，并打印输出 */
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束花括号  */

