/*第四章：编程练习 1*/
#include <iostream>
using namespace std;
/* 预编译指令*/

int main()
{
    char first_name[20], last_name[20];
    char grade;
    int age;
    /* 定义程序中的变量，包括姓名、年纪等 */
    cout<<"What is your first name? ";
    cin.getline(first_name, 20);
    cout<<"What is your last name? ";
    cin.getline(last_name, 20);
    /* 使用getline()函数读取姓名，字符限制在20内 */
    cout<<"What letter grade do you deserve? ";
    cin>>grade;
    cout<<"What is your age? ";
    cin>>age;
    cout<<"Name "<<last_name<<" , "<<first_name<<endl;
    cout<<"Grade: "<<char(grade + 1)<<endl;
    cout<<"Age: "<<age<<endl;
    /* 输出存储的信息 */
    return  0;
}
/* main()函数结束，返回值和花括号 */
