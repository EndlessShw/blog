/*第四章：编程练习 7 */
#include <iostream>
using namespace std;
/* 预编译指令*/
struct Pizza
{
    char company[40];
    float diameter;
    float weight;
};
/* Pizza 结构体的定义 */
int main()
{
    Pizza dinner;
    cout<<"Enter the Pizza's information:"<<endl;
    cout<<"Pizza's Company:";
    cin.getline(dinner.company,40);
    /* 读取用户输入信息，可以直接使用成员运算符*/
    cout<<"Pizza's diameter(inchs): ";
    cin>>dinner.diameter;

    cout<<"CandBar's weight(pounds): ";
    cin>>dinner.weight;
    /* 读取用户输入信息，使用成员运算符表示每一个成员并赋值*/
    cout<<"The lunch pizza is "<<dinner.company<<"."<<endl;
    cout<<"And its diameter is "<<dinner.diameter<<" inch, weight is "<<dinner.weight;
    cout<<"pounds."<<endl;
    /* 输出信息 */
    return  0;
}

