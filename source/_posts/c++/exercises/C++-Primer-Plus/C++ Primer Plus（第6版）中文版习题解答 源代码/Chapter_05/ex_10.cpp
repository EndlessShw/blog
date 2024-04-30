/*第五章：编程练习 10 */
#include <iostream>
using namespace std;

int main()
{
    int line;
    cout<<"Enter the number of rows:";
    cin>>line;
    for(int i = 0; i < line; i++)
    {
        for(int j = 0; j < line - i - 1; j++)
        {
            cout<<".";
        }
        /* 第一个内部循环负责打印句号，句号是逐行递减
         * 因此需要通过 j < line - i -1 来控制每一行的句号数量 */
        for(int j = 0; j <= i; j++)
        {
            cout<<"*";
        }
        /* 第二个内部循环负责打印星号，星号数量是逐行递增，
         * 因此使用j < =i 来控制每一行的星号数量 */
        cout<<endl;
    }
    return 0;
}

