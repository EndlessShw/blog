/*第二章：编程练习5 */
#include <iostream>
using namespace std;
/* 预编译指令*/

float convert(float f);
/* 温度转换函数，将参数中的摄氏温度转换为华氏温度
 * 因此返回值是华氏温度。参数和返回值都是float类型数据 
 * */
int main() 
{
    float c_degree, f_degree;
    /* 声明两个变量，分别存储两种温度数据 */
    cout<<"Please enter a Celsius value:";
    cin>>c_degree;
    /* 读取用户输入的摄氏温度 */
    f_degree = convert(c_degree);
    /* 函数调用，并通过返回值给华氏温度赋值 */
    cout<<c_degree<<" degrees Celsius is ";
    cout<<f_degree<<" degrees Fahrenheit."<<endl;
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束的花括号 */

float convert(float f)
{
    return  f*1.8 + 32;
}
/* 函数的定义，可以直接在返回语句中计算和转换，
*也可以定义一个变量，计算转换值，最后返回该变量
* 例如：
* float temp = f*1.8 + 32；
* return temp；
* */

