//complex.cpp
#include <iostream>
#include "complex0.h"
complex::complex(double realnum, double imagnum)
{
    real = realnum;
    imaginary = imagnum;
}

complex::~complex()
{
}

complex complex::operator+(const complex & c) const
{
    return complex(real + c.real,imaginary + c.imaginary);
}

complex complex::operator-(const complex & c) const
{
    return complex(real - c.real,imaginary - c.imaginary);
}

complex complex::operator*(const complex & c) const
{
    complex temp;
    temp.real = real * c.real - imaginary * c.imaginary;
    temp.imaginary = real * c.imaginary + imaginary * c.real;
    return temp;
}

complex operator*(double x, const complex & c)
{
    return complex(x * c.real,x * c.imaginary);
}
complex complex::operator~() const
{
    return complex(real,-imaginary);
}

std::istream & operator>>(std::istream & is, complex & c)
{
    std::cout << "real: ";
    if (!(is >> c.real))
        return is;
    std::cout << "imaginary: ";
    is >> c.imaginary;
    return is;
}

std::ostream & operator<<(std::ostream & os, const complex & c)
{
    os << "(" << c.real << ", " << c.imaginary << "i)";
    return os;
}


