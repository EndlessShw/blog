/*第六章：编程练习 2
 * */
#include <iostream>
#include <array>
using namespace std;

int main()
{
    array<double ,10> donation;
    /* 使用array模板定义数组，长度为10 */
    double input;
    int counter = 0;
    double average, sum = 0;
    int bigger = 0;
    /* sum，average，counter bigger 分别记录和，平均值，元素数、大于平均值个数 */
    cout<<"Enter the double numerial: ";
    cin>>input;
    while(input != 0 && counter<10)
    {
        donation[counter++] = input;
        cout<<"No."<<counter<<" Data input to Array."<<endl;
        cout<<"Enter the double numerial: ";
        cin>>input;
    }
    /* 通过while循环输入数据，当输入非数字时或大于10个元素时退出循环 */
    for(int i = 0;i < counter; i++)
    {
        sum +=  donation[i];
    }
    average = sum / counter;
    /* 求和并计算平均数 */
    for(int i = 0;i < counter; i++)
    {
        if(donation[i] > average)
            bigger++;
    }
    /* 通过遍历比较大于平均数的个数 */
    cout<<"The Average is "<<average<<" and "<<bigger;
    cout<<" data bigger than average."<<endl;
    return 0;
}


