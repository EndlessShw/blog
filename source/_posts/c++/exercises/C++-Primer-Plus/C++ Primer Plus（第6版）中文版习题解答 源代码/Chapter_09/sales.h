/*第九章：编程练习 4 */
//sales.h
/* SALES头文件，定义了SALES名字空间，及相关的函数*/
namespace SALES
{
    const int QUARTERS = 4;
    struct Sales{
        double sales[QUARTERS];
        double average;
        double max;
        double min;
    };
    void setSales(Sales& s, const double ar[], int n);
    void setSales(Sales& s);
    void showSales(const Sales& s);
}


//sales.cpp
/* sales.cpp，定义了sales.h内的所有函数实现 */
#include <iostream>
#include "sales.h"

using namespace std;
using namespace SALES;
/* 预编译器指令 包含sales.h头文件，SALES名字空间 */
void SALES::setSales(Sales& s, const double ar[], int n)
/* SALES名字空间内函数实现，可以使用作用域运算符标识函数归属 */
{
    double sum = 0;
    if(n >= QUARTERS){
        for(int i = 0;i < QUARTERS; i++)
        {
            s.sales[i] = ar[i];
        }
    }else{
        for(int i = 0;i < n; i++)
        {
            s.sales[i] = ar[i];
        }
        for(int i = n;i < QUARTERS; i++)
        {
            s.sales[i] = 0;
        }
    }
    /* 综合考虑输入数据与QUARTERS不匹配情况下，如何初始化数据
     * 对于数据被舍弃、不足数据被补 0 */
    s.max = s.min = s.sales[0];
    for(int i = 0;i < QUARTERS; i++)
    {
        sum += s.sales[i];
        if(s.min>s.sales[i]) s.min = s.sales[i];
        if(s.max<s.sales[i]) s.max = s.sales[i];
    }
    /* 初始化 最大值和最小值 */
    s.average = sum / QUARTERS;
}

void SALES::setSales(Sales& s)
{
    double ar[QUARTERS] = {};
    int i = 0;
    do{
        cout<<"Enter a number: ";
        if(!(cin>>ar[i]))
        {
            cin.clear();
            while(cin.get()!='\n') continue;
            cout<<"ERROE, Reenter a number: ";
            cin>>ar[i];
        }
        i++;
    }while(i < QUARTERS);
    /* 交互输入QUARTERS个数据，并存储在数组内 */
    setSales(s,ar,4);
    /* 通过重载函数初始化Sales */
}

void SALES::showSales(const Sales& s)
{
    cout<<"This Salse's quarter list info:"<<endl;
    for(int i = 0; i < QUARTERS; i++)
    {
        cout<<"No."<<i+1<<": sales: "<<s.sales[i]<<endl;
    }
    cout<<"AVERAGE: "<<s.average<<endl;
    cout<<"MAX: "<<s.max<<endl;
    cout<<"MIX: "<<s.min<<endl;
}
