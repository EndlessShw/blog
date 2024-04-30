/*第五章：编程练习 1 */
#include <iostream>
using namespace std;

int main()
{
    int min, max, sum = 0;
    /* 定义输入数据变量和求和变量 */
    cout<<"Enter the first numeral: ";
    cin>>min;
    cout<<"Enter the second numeral: ";
    cin>>max;
    /* 通过标准输入读取起止范围数据 */
    for(int i = min; i<=max; i++)
        sum += i;
    /* 通过for循环，计算两数范围内所有整数的和 */
    cout<<"The sum of "<<min<<" +...+ "<<max<<" is ";
    cout<<sum<<endl;
    return  0;
}


