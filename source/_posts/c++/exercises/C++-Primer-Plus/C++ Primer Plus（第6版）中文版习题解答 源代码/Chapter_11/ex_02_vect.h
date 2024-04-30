/*第十一章：编程练习 2 */
// vect.h -- Vector class with <<, mode state
#ifndef VECTOR_H_
#define VECTOR_H_
#include <iostream>
namespace VECTOR
{
    class Vector
    {
    public:
        enum Mode {RECT, POL};
        // RECT for rectangular, POL for Polar modes
    private:
        double x;          // horizontal value
        double y;          // vertical value
        Mode mode;         // RECT or POL
        /* 按照题目要求删除mag和ang两个数据成员。
        double mag;        // length of vector
        double ang;        // direction of vector in degrees
        */
        // private methods for setting values
        /* 删除mag和ang数据成员后，相应的两个相关私有成员函数也将不再使用
        void set_mag();
        void set_ang();
        */
        void set_x(double mag, double ang);       //通过用户输入的mag和ang求x
        void set_y(double mag, double ang);       //通过用户输入的mag和ang求y
    public:
        Vector();
        Vector(double n1, double n2, Mode form = RECT);
        void reset(double n1, double n2, Mode form = RECT);
        ~Vector();
        double xval() const {return x;}       // report x value
        double yval() const {return y;}       // report y value
        /* 成员函数magval()和 angval()可以使用两种方式实现
        1. 此处也可以修改原内联函数，直接计算数值并返回，例如：
        double magval() const ( return sqrt(x * x + y * y);)
        double angval() const {
            if (x == 0.0 && y == 0.0)
                return 0.0;
            else
                return atan2(y, x);
            }
        2.以如下形式，修改为非内联函数，并在vect.cpp中定义。
        */
        double magval() const;           // report magnitude
        double angval() const;              // report angle
        void polar_mode();                    // set mode to POL
        void rect_mode();                     // set mode to RECT
        // operator overloading
        Vector operator+(const Vector & b) const;
        Vector operator-(const Vector & b) const;
        Vector operator-() const;
        Vector operator*(double n) const;
        // friends
        friend Vector operator*(double n, const Vector & a);
        friend std::ostream & operator<<(std::ostream & os, const Vector & v);
    };

}   // end namespace VECTOR
#endif
