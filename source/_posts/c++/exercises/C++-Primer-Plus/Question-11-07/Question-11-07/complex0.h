#pragma once
#ifndef COMPLEX0_H_
#define COMPLEX0_H_
#include<iostream>
using namespace std;
// 定义复数类
class Complex {
private:
	double real = 0, imaginary = 0;
	
public:
	// 构造函数
	Complex(double real, double imaginary);
	Complex();
	// 两个 setter
	void setReal(double real);
	void setImaginary(double imaginary);
	// 两个 getter 访问私有成员（但是不能修改）
	double getReal() const;
	double getImaginary() const;
};

// 重载左移运算符
ostream& operator << (ostream& cout, const Complex complex);
// 重载右移运算符
istream& operator >> (istream& cin, Complex& complex);
// 重载 + - * / 运算符
Complex operator + (const Complex complex1, const Complex complex2);
Complex operator - (const Complex complex1, const Complex complex2);
Complex operator * (const Complex complex1, const Complex complex2);
Complex operator * (const double x, const Complex complex1);
Complex operator ~ (const Complex complex1);
#endif