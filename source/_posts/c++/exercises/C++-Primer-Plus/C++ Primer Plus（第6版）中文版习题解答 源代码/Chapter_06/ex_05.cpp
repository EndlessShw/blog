/*第六章：编程练习 5
 * */
#include <iostream>

using namespace std;
int main()
{
    float tax, salary = 0.0;
    cout<<"Hello, enter your salary to calculate tax:";
    cin>>salary;
    /* 读取用户输入的工资 */
    while(salary > 0)
    {
        if(salary <= 5000)
        {
            tax = 0;
        }else if(salary <= 15000)
        {
            tax = (salary - 5000)*0.10;
        }else if(salary <= 35000)
        {
            tax = 10000*0.10 + (35000-15000)*0.15;
        }else if(salary > 35000)
        {
            tax = 10000*0.10 + 20000*0.15 + (salary - 35000)*0.20;
        }
        /* 通过多重选择进行判断，这里需要注意的是条件表达式 并为使用与或非的逻辑运算符
         * 例如salary <= 35000的条件，当能够进行改条件语句判断时，salary必然已经大于15000
         * */
        cout<<"Your salary is "<<salary<<" tvarps, and you should pay ";
        cout<<tax<<" tvarps."<<endl;
        cout<<"enter your salary to calculate tax:";
        cin>>salary;
    }
    cout<<"Bye!"<<endl;
    return 0;
}
