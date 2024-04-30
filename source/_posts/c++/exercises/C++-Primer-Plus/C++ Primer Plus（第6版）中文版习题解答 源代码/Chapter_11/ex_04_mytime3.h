/*第十一章：编程练习 4 */
// mytime3.h -- Time class with friends
#ifndef MYTIME3_H_
#define MYTIME3_H_
#include <iostream>

class Time
{
private:
    int hours;
    int minutes;
public:
    Time();
    Time(int h, int m = 0);
    void AddMin(int m);
    void AddHr(int h);
    void Reset(int h = 0, int m = 0);

    /*修改原有的成员函数的操作符重载方式，使用友元函数中需要注意修改函数的参数
     新添加一个Time类型的参数。为了保持和原有成员函数类似，下面的友元函数实现
    并为修改返回值。且友元函数不需要使用const关键字描述函数的属性
    */
    friend Time operator+(const Time & s, const Time & t);
    friend Time operator-(const Time & s, const Time & t);
    friend Time operator*(const Time & s, double n);

    /* 以下为原有的友元函数 */
    friend Time operator*(double m, const Time & t)
    { return t * m; }   // inline definition
    friend std::ostream & operator<<(std::ostream & os, const Time & t);

};
#endif
