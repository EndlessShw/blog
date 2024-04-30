/*第五章：编程练习 4 */
#include <iostream>
using namespace std;
const int DEPOSIT_BASE = 100;
/* 定义基准常量 */
int main()
{
    float daphne_deposit = DEPOSIT_BASE;
    float cleo_deposit = DEPOSIT_BASE;
    /* 定义并初始化两人的起始金额 */
    int year = 0;
    while(daphne_deposit>=cleo_deposit)
    {
        /* 循环条件 daphone 大于 cleo 执行循环，否则终止 */
        cout<<"In "<<year++<<" Year: Daphne = "<<daphne_deposit<<endl;
        cout<<"\tCleo = "<<cleo_deposit<<endl;
        daphne_deposit += 0.1*DEPOSIT_BASE;
        /* 计算daphone 每年后的总金额 */
        cleo_deposit += 0.05*cleo_deposit;
        /* 计算cleo每年后的总金额 */
    }
    cout<<"In "<<year<<" year: Daphne = "<<daphne_deposit<<endl;
    cout<<"\tCleo = "<<cleo_deposit<<endl;
    return  0;
}

