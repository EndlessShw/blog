/*第十四章：编程练习 1 */
#ifndef WINEC_H
#define WINEC_H

#include <iostream>
#include <string>
#include <valarray>
using namespace std;

template <class T1, class T2> class Pair;
/* Pair模板类的声明 */
typedef std::valarray<int> ArrayInt;
typedef Pair<ArrayInt,ArrayInt> PairArray;
/* PairArray中两个类型参数相同，均为ArrayInt */

template <class T1, class T2>
class Pair
{
private:
    T1 a;
    T2 b;
public:
    T1 & first();
    T2 & second();
    T1 first() const { return a; }
    T2 second() const { return b; }
    Pair(const T1 & aval, const T2 & bval) : a(aval), b(bval) { }
    Pair() {}
};

class Wine
{
private:
    string label;
    PairArray info;
   /* Pair模板类对象存储 Wine的年份和对应数量*/
     int year;
public:
    Wine(const char* l, int y,const int yr[],const int bot[]);
    Wine(const char* l, int y);
    void GetBottles();
    const string& Label() const;
    int sum() const;
    void Show();
};
#endif
