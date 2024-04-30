/*第八章：编程练习 3 */
#include <iostream>
#include <string>
using namespace std;

void uppercase(string& s);
/* 函数声明 */
int main() 
{
    string st;
    cout<<"Enter a string (q to quit): ";
    getline(cin, st);
    while(st != "q")
    /* 输入字符 q 退出循环 */
    {
        uppercase(st);
        cout<<st<<endl;
        cout<<"Next string (q to quit): ";
        getline(cin, st);
    }
    cout<<"Bye."<<endl;
    return 0;
}
void uppercase(string& s)
{
    for( int i = 0; i < s.size(); i++){
        s[i] = toupper(s[i]);
    }
    /* 使用字符串的数组特性，逐一修改大小写 */
}

