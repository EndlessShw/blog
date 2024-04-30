/*第四章：编程练习 5 */
#include <iostream>
using namespace std;
/* 预编译指令*/
struct CandyBar
{
    char brand[20];
    float weight;
    unsigned int calorie;
};
/* CandyBar结构体的定义 */
int main()
{
    CandyBar snack = {"Mocha Munch", 2.3, 350};
    /* 定义snack变量，并初始化 */
    cout<<"My favourite CandyBar is "<<snack.brand<<"."<<endl;
    cout<<"And its weight is "<<snack.weight<<", calorie is "<<snack.calorie;
    cout<<"."<<endl;
    /* 显示snack 的基本信息*/
    return  0;
}
