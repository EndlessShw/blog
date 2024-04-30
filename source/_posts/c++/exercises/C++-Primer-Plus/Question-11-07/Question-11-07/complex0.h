#pragma once
#ifndef COMPLEX0_H_
#define COMPLEX0_H_
#include<iostream>
using namespace std;
// ���帴����
class Complex {
private:
	double real = 0, imaginary = 0;
	
public:
	// ���캯��
	Complex(double real, double imaginary);
	Complex();
	// ���� setter
	void setReal(double real);
	void setImaginary(double imaginary);
	// ���� getter ����˽�г�Ա�����ǲ����޸ģ�
	double getReal() const;
	double getImaginary() const;
};

// �������������
ostream& operator << (ostream& cout, const Complex complex);
// �������������
istream& operator >> (istream& cin, Complex& complex);
// ���� + - * / �����
Complex operator + (const Complex complex1, const Complex complex2);
Complex operator - (const Complex complex1, const Complex complex2);
Complex operator * (const Complex complex1, const Complex complex2);
Complex operator * (const double x, const Complex complex1);
Complex operator ~ (const Complex complex1);
#endif