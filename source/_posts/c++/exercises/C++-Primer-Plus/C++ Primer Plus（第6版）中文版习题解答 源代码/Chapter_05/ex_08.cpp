/*第五章：编程练习 8 */
#include <iostream>
#include <cstring>
using namespace std;

const int SIZE = 20;
const char FINISHED[] = "done";
/* 定义常量 */
int main()
{
    int counter = 0;
    char words[SIZE];
    cout<<"Enter words (to stop, type the word done):"<<endl;
    while(strcmp(FINISHED,words) != 0 )
    {
        counter++;
        cin>>words;
        cin.get();
        /* 题目要读取单词，因此使用cin，并使用get()删除空白 
         * 循环条件是输入单词不是"done" 使用字符串比较函数
         * */
    }
    cout<<"You entered a total of "<<counter-1<<" words."<<endl;
    return 0;
}


