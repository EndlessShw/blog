/*第七章：编程练习 5
 * */
#include <iostream>
using namespace std;

long long factorial(int);
/* 阶乘函数的原型 */
int main() 
{
    int n;
    cout<<"Enter a number to calc factorial: ";
    cin>>n;
    while(n > 0)
    {
        cout<<n<<"! = "<<factorial(n)<<endl;
        cout<<"Enter a number to calc factorial: ";
        cin>>n;
    }
    cout<<"Done!"<<endl;
    return 0;
}
long long factorial(int n)
{
    if(n == 0) 
    {
        return 1;
        /* 函数的第一条语句，0！作为递归返回点 */
    }else{
        return n * factorial(n-1);
    }
}

