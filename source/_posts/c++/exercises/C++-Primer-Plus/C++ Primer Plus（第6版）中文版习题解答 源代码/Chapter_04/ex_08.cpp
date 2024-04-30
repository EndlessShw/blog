/*第四章：编程练习 8 */
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
    Pizza* ppizza = new Pizza;
    cout<<"Enter the Pizza's information:"<<endl;
    cout<<"Pizza's diameter(inchs): ";
    cin>>ppizza->diameter;

    cout<<"Pizza's Company:";
    cin.getline(ppizza->company,40);

    cout<<"CandBar's weight(pounds): ";
    cin>>ppizza->weight;
    /* 指针变量需要使用 -> 成员运算符而不是“ .” 成员运算符 */
    cout<<"The lunch pizza is "<<ppizza->company<<"."<<endl;
    cout<<"And its diameter is "<<ppizza->diameter<<" inch, weight is "<<ppizza->weight;
    cout<<"pounds."<<endl;
    delete ppizza;
    /* 程序结束，必须手动调用delete 回收存储空间*/
    return  0;
}

