/*第十一章：编程练习 7 */
//complex0.h
#ifndef COMPLEX0_H_
#define COMPLEX0_H_

class complex
{
private:
    double real;
    double imaginary;
public:
    complex(double real = 0.0, double imaginary = 0.0);
    ~complex();

    complex operator+(const complex & c) const;
    complex operator-(const complex & c) const;
    complex operator*(const complex & c) const;
    complex operator~() const;

    friend complex operator*(double x, const complex & c);
    friend std::istream & operator>>(std::istream & is, complex & c);
    friend std::ostream & operator<<(std::ostream & os, const complex & c);
};
#endif

