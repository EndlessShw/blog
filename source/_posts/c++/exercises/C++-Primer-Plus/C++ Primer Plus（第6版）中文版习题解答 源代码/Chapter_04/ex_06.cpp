/*第四章：编程练习 6 */
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
    CandyBar snack[3] = {{"Mocha Munch", 2.3, 350},{"Hershey bar", 4.2, 550},{"Musketeers", 2.6, 430}};
    /* 创建结构体数组，并使用花括号嵌套的方式进行初始化 */
    cout<<"My 1st CandyBar is "<<snack[0].brand<<"."<<endl;
    cout<<"And its weight is "<<snack[0].weight<<", calorie is "<<snack[0].calorie;
    cout<<"."<<endl;
    /* 通过数组下标 加成员运算符的方式，可以访问数组内元素的数据成员 */
    cout<<"My 2nd CandyBar  is "<<snack[1].brand<<"."<<endl;
    cout<<"And its weight is "<<snack[1].weight<<", calorie is "<<snack[1].calorie;
    cout<<"."<<endl;

    cout<<"My 3th CandyBar  is "<<snack[2].brand<<"."<<endl;
    cout<<"And its weight is "<<snack[2].weight<<", calorie is "<<snack[2].calorie;
    cout<<"."<<endl;
    /* 显示snack 的数据信息*/
    return  0;
}
