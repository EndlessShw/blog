/*第十二章：编程练习 2 */
#ifndef STRING2_H_
#define STRING2_H_
#include <iostream>
using std::ostream;
using std::istream;

class String
{
private:
    char * str;             // pointer to string
    int len;                // length of string
    static int num_strings; // number of objects
    static const int CINLIM = 80;  // cin input limit
public:
// constructors and other methods
    String(const char * s); // constructor
    String();               // default constructor
    String(const String &); // copy constructor
    ~String();              // destructor
    int length () const { return len; }
// overloaded operator methods
    String & operator=(const String &);
    String & operator=(const char *);
    char & operator[](int i);
    const char & operator[](int i) const;
    /* 添加新的运算符重载，+ 使用友元函数的方式实现。
     * 依据题目要求田间stringlow()和stringup()函数
     * 函数无返回值，无参数，直接修改私有成员str。*/
    //String operator+(const String &s) const;
    //可以使用成员函数重载两个String加法，也可以用友元函数，如下：
    friend String operator+(const char * s, const String &st);
    friend String operator+(const String &s, const String &st);
    /* 题目要求实现字符指针和String加法，以及两个String对象相加，因此需要两个运算符重载
     * 函数，两者在函数的参数上不同。可以使用成员函数或者友元函数，*/
    void stringlow();
    void stringup();
    int has(char c) const;
    /**/
// overloaded operator friends
    friend bool operator<(const String &st, const String &st2);
    friend bool operator>(const String &st1, const String &st2);
    friend bool operator==(const String &st, const String &st2);
    friend ostream & operator<<(ostream & os, const String & st);
    friend istream & operator>>(istream & is, String & st);
// static function
    static int HowMany();
};
#endif
