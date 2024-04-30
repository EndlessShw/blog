/*第六章：编程练习 1
 * */
#include <iostream>
#include <cctype>
/* 使用toupper()函数需要 添加cctype头文件 */
using namespace std;

int main()
{
    char input;
    cout<<"Enter the character: ";
    cin.get(input);
    while(input != '@')
    {
        /* 循环入口条件是输入字符不等于 @ */
        if(isdigit(input))
        {
            /* 输入数据是数字时的处理方法 */
            cin.get(input);
            continue;
        }else if(islower(input))
        {
            input = toupper(input);
            /* 小写字母处理方法 */
        }else if(isupper(input))
        {
            input = tolower(input);
            /* 大些字母处理方法 */
        }
        /* 通过多重条件语句处理输入数据 */
        cout<<input;
        cin.get(input);
    }
    cout<<"\nDONE."<<endl;
    return 0;
}
