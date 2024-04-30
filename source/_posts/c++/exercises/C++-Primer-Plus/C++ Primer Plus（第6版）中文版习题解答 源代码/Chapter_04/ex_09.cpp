/*第四章：编程练习 9 */
#include <iostream>
using namespace std;
/* 预编译指令*/
struct CandyBar
{
    char brand[20];
    float weight;
    unsigned int calorie;
};
/* CandyBar 结构体的定义 */
int main()
{
    CandyBar* pc = new CandyBar[3];
    strcpy(pc[0].brand, "Mocha Munch");
    pc[0].weight = 2.3;
    pc[0].calorie = 350;
    strcpy(pc[1].brand, "Hershey bar");
    (pc + 1)->weight = 4.2;
    pc[1].calorie = 550;
    strcpy(pc[2].brand, "Musketeers");
    pc[2].weight = 2.6;
    pc[2].calorie = 430;
    /* 本处按照数组形式表示元素，也可以使用如下形式：
     *(pc)->weight = 4.2;
     *(pc + 1)->weight = 4.2;
     *(pc + 2)->weight = 4.2;
     *形式表示数组元素的成员。下面的打印使用这种方式，
     * 可以对比使用。
     * */
    cout<<"My 1st CandyBar is "<<pc->brand<<"."<<endl;
    cout<<"And its weight is "<<pc->weight<<", calorie is "<<pc->calorie;
    cout<<"."<<endl;

    cout<<"My 2nd CandyBar  is "<<(pc+1)->brand<<"."<<endl;
    cout<<"And its weight is "<<(pc+1)->weight<<", calorie is "<<(pc+1)->calorie;
    cout<<"."<<endl;

    cout<<"My 3th CandyBar  is "<<(pc+2)->brand<<"."<<endl;
    cout<<"And its weight is "<<(pc+2)->weight<<", calorie is "<<(pc+2)->calorie;
    cout<<"."<<endl;
    delete [] pc;
    /* 程序结束，必须手动调用delete 回收存储空间*/
    return  0;
}

