/*第七章：编程练习 4 */
#include<iostream>
using namespace std;

long double probability(double fnumbers, double snumber, double picks);
/* 修改程序中的计算多选多的中奖几率，添加特别号码的数字  */
int main()
{
    cout << "Field number is 45 , and special number is 27 ."<<endl;
    cout << "the probability is : one of the "<<probability(45,27,5)<<endl;
    return 0;
}
long double probability(double fnumbers, double snumber, double picks)
{
    long double result = 1.0;
    long double n;
    unsigned p;
    for(n = fnumbers, p = picks ; p > 0; n--, p--)
        result = result * n / p;
    /* 首先计算域号码的选中几率 */
    return result /=  snumber ;
    /* 域号码几率乘以特选号码几率*/
}
