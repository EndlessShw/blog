/*第十章：编程练习 3 */
/* golf.cpp 包含类内成员函数的实现，
 * 本例也包含了main()函数 */
#include <iostream>
#include <cstring>
#include "golf.h"

using namespace std;

int main()
{
    golf ann("Ann Bird free",24);
    golf andy;

    ann.showgolf();
    andy.showgolf();
    return 0;
}

golf::golf(const char* name, int hc)
{
    strcpy(fullname, name);
    handicap = hc;
}/* 构造函数的定义 应添加作用域运算符 */

golf::golf()
{
    char name[Len] = {'\0'};
    int hc;
    cout<<"Please enter the name: ";
    cin.getline(name,Len);

    cout<<"Please enter the handicap: ";
    while(!(cin>>hc))
    {
        cin.clear();
        while(cin.get() != '\n')
            continue;
        cout<<"Please enter the golf's handicap: ";
    }
    cout<<name<<"::"<<hc<<endl;
    strcpy(fullname, name);
    handicap = hc;
}
/* 缺省构造函数，通过交互方式，输入对象信息 */
void golf::sethandicap(int hc)
{
    handicap = hc;
}

void golf::showgolf( ) const
{
    cout<<"Name : "<<fullname<<", Handicap is "<<handicap<<endl;
}
/* 对象信息打印函数，不修改数据成员，应添加const关键字 */
