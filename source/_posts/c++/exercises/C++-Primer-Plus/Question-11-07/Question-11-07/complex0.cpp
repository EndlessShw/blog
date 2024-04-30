#include <iostream>
#include "complex0.h"

// 可以用初始化列表
Complex::Complex(double real, double imaginary)
{
	this->real = real;
	this->imaginary = imaginary;
}

Complex::Complex(){}

void Complex::setReal(double real)
{
	this->real = real;
}

void Complex::setImaginary(double imaginary)
{
	this->imaginary = imaginary;
}

double Complex::getReal() const
{
	return this->real;
}

double Complex::getImaginary() const
{
	return this->imaginary;
}

ostream& operator << (ostream& cout, const Complex complex)
{
	cout << "(" << complex.getReal() << ", " 
		<< complex.getImaginary() << "i)" << endl;
	return cout;
}

istream& operator >> (istream& cin, Complex& complex)
{
	double real = 0, imaginary = 0;

	cout << "real: ";
	// 特殊的知识点：
	// 如果 cin 输入的类型非法，那么输入流异常，cin 为 null 且 cin >> 表达式返回 false
	if (!(cin >> real))
	{
		return cin;
	}
	cin.get();
	cout << endl;
	cout << "imaginary: ";
	cin >> imaginary;
	cin.get();
	cout << endl;

	complex.setReal(real);
	complex.setImaginary(imaginary);
	return cin;
}

Complex operator + (const Complex complex1, const Complex complex2)
{
	Complex complex{};
	complex.setReal(complex1.getReal() + complex2.getReal());
	complex.setImaginary(complex1.getImaginary() + complex2.getImaginary());
	return complex;
}

Complex operator - (const Complex complex1, const Complex complex2)
{
	Complex complex{};
	complex.setReal(complex1.getReal() - complex2.getReal());
	complex.setImaginary(complex1.getImaginary() - complex2.getImaginary());
	return complex;
}

Complex operator * (const Complex complex1, const Complex complex2)
{
	Complex complex{};
	complex.setReal(complex1.getReal() * complex2.getReal() - complex1.getImaginary() * complex2.getImaginary());
	complex.setImaginary(complex1.getReal() * complex2.getImaginary() + complex1.getImaginary() * complex2.getReal());
	return complex;
}

Complex operator * (const double x, const Complex complex1)
{
	Complex complex{};
	complex.setReal(x * complex1.getReal());
	complex.setImaginary(x * complex1.getImaginary());
	return complex;
}

Complex operator ~ (const Complex complex1)
{
	Complex complex{};
	complex.setReal(complex1.getReal());
	complex.setImaginary(-complex1.getImaginary());
	return complex;
}

