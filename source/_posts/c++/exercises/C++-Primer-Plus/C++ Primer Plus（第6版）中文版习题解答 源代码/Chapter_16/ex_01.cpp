/*第十六章：编程练习 1 */
#include <iostream>
#include <string>
using namespace std;

bool palindromic(string& s);

int main()
{
    string st;
    cout<<"Enter the string to test: ";
    getline(cin, st);
    cout<<st<<endl;
    cout<<palindromic(st);
    return 0;
}

bool palindromic(string& s)
{
    string temp = s;
    reverse(temp.begin(), temp.end());
    /* 翻转输入字符串s，并进行比较，如果需要自己实现字符串翻转
     * 可以使用循环，交换首末位字符即可 */
    return (s == temp);
    /* 翻转前后相等即返回真。*/
}
