/*第十四章：编程练习 4 */
#ifndef PERASON_H
#define PERASON_H

#include <iostream>
#include <string>
// create the pers and debts namespaces
using namespace std;
class Person
{
private:
    string fname;
    string lname;
public:
    Person():fname("no name"),lname("no name"){};
    Person(string f,string l);
    virtual ~Person(){};
    virtual void Show() const;
};
/* 基类Person的声明 */

class Gunslinger:virtual public Person
{
private:
    int nick;
/* 新增数据成员 */
public:
    Gunslinger():Person(),nick(0){ };
    Gunslinger(string f,string l,int n);
    ~Gunslinger(){};
    double Draw();
    void Show()const;
/* 新增成员函数，隐藏Show()函数 */
};
/* 派生类Gunslinger，虚继承自Person类 */


struct Card{
    enum SUITE {SPADE,HEART,DIAMOND,CLUB};
    SUITE suite;
    int number;
};
/* Card结构的定义 */

class PokerPlayer:virtual public Person
{
public:
    ~PokerPlayer(){};
    Card Draw() const;
    /* 新增成员函数*/
};
/* 派生类PokerPlayer，虚继承自Person类 */

class BadDude: public Gunslinger,public PokerPlayer
{
public:
    double GDraw() const;
    int CDraw() const;
    void Show() const;
/* 新增成员函数，隐藏Draw()函数 */
};
/* 派生类BadDude，继承自PokerPlayer，Gunslinger类 */
#endif //
