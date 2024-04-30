/*第五章：编程练习 2 */
#include <iostream>
#include <array>

const int ArSize = 101;
using namespace std;

int main()
{
    array<long double, ArSize> factorials;
    factorials[1] = factorials[0] = 1;
    /*初始化阶乘中的0！和 1！*/
    for(int i = 2;i < ArSize; i++)
        factorials[i] = i * factorials[i-1];
    /* 根据阶乘定义，应用for循环计算100的阶乘，注意此处计算了100以内所有数的阶乘 */
    for(int i = 0; i < ArSize;i++)
        cout<<i<<"! = "<<factorials[i]<<endl;
    /* 使用for循环打印阶乘结果数据*/
    return  0;
}

