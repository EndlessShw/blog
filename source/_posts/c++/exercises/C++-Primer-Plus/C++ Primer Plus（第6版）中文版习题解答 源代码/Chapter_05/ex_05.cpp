/*第五章：编程练习 5 */
#include <iostream>
using namespace std;
int main()
{
    const string Month[] = {"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
    int sale_amount[12]={};
    /* 定义两个数组，分别初始化为月份数据 和销售数据，销售数据通过{}初始化为0 */
    unsigned int sum = 0;
    for(int i = 0; i < 12; i++)
    {
        cout<<"Enter the sale amount of "<<Month[i]<<" :";
        cin>>sale_amount[i];
    }
    /* 通过循环，读取用户输入 */
    cout<<"Input DONE!"<<endl;

    for(int i = 0; i < 12; i++)
    {
        cout<<Month[i]<<" SALE :"<<sale_amount[i]<<endl;
        sum += sale_amount[i];
    }
    /* 通过循环再次计算总销售额 */
    cout<<"Total sale "<<sum<<" this year."<<endl;    return  0;
}

