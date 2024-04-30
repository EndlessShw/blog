/*第三章：编程练习 6 */
#include <iostream>
using namespace std;
/* 预编译指令*/

int main()
{
    float distance_in_mile, distance_in_km;
    float fuel_in_gallon, fuel_in_litre;
    float fuel_consume;
    /* 变量声明 */
    cout<<"Enter the distance in miles: ";
    cin>>distance_in_mile;
    cout<<"Enter the fuel consume in gallon: ";
    cin>>fuel_in_gallon;
    fuel_consume = distance_in_mile / fuel_in_gallon;
    /* 读取数据，并计算美式油耗 */
    cout<<"The fuel consume is "<<fuel_consume<<" mpg(miles/gallon)."<<endl;
    cout<<"Enter the distance in kilometer: ";
    cin>>distance_in_km;
    cout<<"Enter the fuel consume in litre: ";
    cin>>fuel_in_litre;
    fuel_consume = (fuel_in_litre / distance_in_km)*100;
    /* 计算欧式油耗 */
    cout<<"The fuel consume is "<<fuel_consume<<"L/100KM."<<endl;
    return  0;
}
/* main()函数结束，注意函数返回值和表示结束花括号  */


