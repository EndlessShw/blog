/*第八章：编程练习 2 */
#include <iostream>
#include <string>
using namespace std;

struct CandyBar{
    string brand;
    float weight;
    int calorie;
};
void create_candy(CandyBar& candy, string s = "Millennium Munch",float w = 2.85, int c = 350);
void show_candy(const CandyBar& candy);
/* 函数声明，默认参数在声明处指定 */
int main()
{
    CandyBar cb;
    create_candy(cb);
    /* 使用默认参数，创建CandyBar 变量cb信息 */
    show_candy(cb);
    create_candy(cb,"Nestle",1.2,200);
    /* 使用非默认参数，创建CandyBar 变量cb信息 */
    show_candy(cb);
    return 0;
}
void create_candy(CandyBar& candy, string s ,float w, int c)
{
    candy.brand = s;
    candy.weight = w;
    candy.calorie = c;
    /* 使用string ，可以通过直接 赋值形式 candy.brand = s;，字符数组需要调用函数。*/
}
void show_candy(const CandyBar& candy)
{
    cout<<"The candybar is made by "<<candy.brand;
    cout<<" and its weight "<<candy.weight<<", ";
    cout<<candy.calorie <<" calorie"<<endl;
}
