/*第四章：编程练习 2 */
#include <iostream>
#include <string>
/* 使用string应当修改#include指令，添加string头文件 */
using namespace std;
/* 预编译指令*/

int main()
{
    string name;
    string dessert;
    /* string能够自动维护字符串长度，因此不需要长度常量 */
    cout<<"Enter your name:\n";
    getline(cin,name);
    cout<<"Enter your favorite dessert:\n";
    getline(cin,dessert);
    /* getline()函数参数和字符数组的cin.getline()不同，这点需要重视 */
    cout<<"I have some delicious "<<dessert;
    cout<<" for you, "<<name<<"\n";
    return  0;
}
/* main()函数结束，返回值和花括号 */

