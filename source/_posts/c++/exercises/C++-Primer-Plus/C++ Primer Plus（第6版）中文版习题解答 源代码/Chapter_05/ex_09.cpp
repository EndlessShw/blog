/*第五章：编程练习 9 */
#include <iostream>
#include <string>
using namespace std;

const char FINISHED[] = "done";
/* 定义常量 */
int main()
{
    int counter = 0;
    string words;
    cout<<"Enter words (to stop, type the word done):"<<endl;
    while( words != FINISHED)
    {
        /* string 判断字符串相等，可以直接使用 == 运算符 */
        counter++;
        cin>>words;
        cin.get();
    }
    cout<<"You entered a total of "<<counter-1<<" words."<<endl;
    return 0;
}

