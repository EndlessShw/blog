/*第十四章：编程练习 2 */
#ifndef WINEC_H
#define WINEC_H

#include <iostream>
#include <string>
#include <valarray>
using namespace std;

template <class T1, class T2> class Pair;
typedef std::valarray<int> ArrayInt;
typedef Pair<ArrayInt,ArrayInt> PairArray;

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

class Wine: private PairArray, private string
/* 原有的两个数据成员修改为私有继承 */
{
private:
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
