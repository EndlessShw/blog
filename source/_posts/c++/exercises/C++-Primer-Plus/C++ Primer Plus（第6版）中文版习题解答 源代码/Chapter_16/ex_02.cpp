/*第十六章：编程练习 2 */
#include <iostream>
#include <cctype>
using namespace std;

bool palindromic(string& s);

int main()
{
    string st;
    cout<<"Enter the string to test: ";
    getline(cin, st);
    cout<<"String "<<st<<" is ";
    if(palindromic(st))
        cout<<"a palindromic string. "<<endl;
    else
        cout<<"not a palindromic string."<<endl;

}
bool palindromic(string& s)
{
    /* 该算法忽略了全部非字母的情况，如果要排除这种情况，需要添加一个判断标识。 */
    //std::string::iterator phead, ptail;
    auto phead = s.begin();
    auto ptail = s.end();
    /* 可以使用两种方式定义头尾的迭代器 */
    while(ptail > phead){
        if(!isalpha(*phead))
        {
            phead++;
            continue;
        }
        /* 忽略头部非字母字符 */
        if(!isalpha(*ptail))
        {
            ptail--;
            continue;
        }
        /* 忽略尾部非字母字符 */
        if(toupper(*phead) == toupper(*ptail))
        {
            phead++;
            ptail--;
        }else
        {
            return false;
        }
    }
    return true;
}

