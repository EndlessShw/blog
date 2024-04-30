/*第三章：编程练习 7 */
#include <iostream>
using namespace std;
/* 预编译指令*/
const float GALLON_TO_LITER = 3.875;
const float HKM_TO_MILE = 62.14;
/* 常量作为数据转换因子*/
int main()
{
    float fuel_consume_eur, fuel_consume_us;
    /* 定义变量 */
    cout<<"Enter the fuel consume in europe(l/100km): ";
    cin>>fuel_consume_eur;

    fuel_consume_us = HKM_TO_MILE / (fuel_consume_eur / GALLON_TO_LITER);
    /* 数据转换 将美式油耗，转换成为欧式 */
    cout<<"The fuel consume is "<<fuel_consume_eur<<"L/100KM."<<endl;
    cout<<"The fuel consume is "<<fuel_consume_us<<" mpg(mile/gallon)."<<endl;
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束花括号  */


