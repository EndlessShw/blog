/*第四章：编程练习 10 */
#include <iostream>
#include <array>
using namespace std;
/* 预编译指令，需要添加 array */

int main()
{
    array<float,3> record_list;
    /* 定义array 对象 record_list */
    float average;
    cout<<"Please input three record of 40 miles.\n";
    cout<<"First recond:";
    cin>>record_list[0];
    cout<<"Second recond:";
    cin>>record_list[1];
    cout<<"Third recond:";
    cin>>record_list[2];
    /* 依次读取数据输入 */
    cout<<"Ok, you input:\n1."<<record_list[0]<<"\n2."<<record_list[1]<<"\n3.";
    cout<<record_list[2]<<endl;
    average = (record_list[0]+record_list[1]+record_list[2])/3;
    /* 计算平均值，并输出 */
    cout<<"Congratulate, your average performance is "<<average<<".";
    return  0;
}
