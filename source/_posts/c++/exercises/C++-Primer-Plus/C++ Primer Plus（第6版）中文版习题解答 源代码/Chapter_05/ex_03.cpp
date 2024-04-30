/*第五章：编程练习 3 */
#include <iostream>
using namespace std;

int main()
{
    double temp, sum = 0;
    do{
        cout<<"Input a numeral to add: ";
        cin>>temp;
        sum += temp;
        /* 读取输入，并求和 */
    }while(temp != 0);
    /* 当输入为0 时退出循环 */
    cout<<"Input end.\n"<<"The sum = "<<sum<<endl;
    return  0;
}

