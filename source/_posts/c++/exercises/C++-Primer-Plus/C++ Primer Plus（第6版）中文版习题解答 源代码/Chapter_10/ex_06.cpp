/*第十章：编程练习 6 */
#include <iostream>

using namespace std;
class Move{
private:
    double x;
    double y;
public:
    Move(double a = 0, double b = 0);
    void showmove() const;
    Move add(const Move & m) ;
    void reset(double a = 0, double b = 0);
};

int main(int argc, char *argv[]) 
{
    Move a, b(12.5,19);
    double x, y;
    a.showmove();
    b.showmove();
    /* a使用构造函数默认值，b使用参数初始化，打印两个对象的信息*/
    cout<<"Enter X and Y: ";
    cin>>x>>y;
    cout<<"Reste Object A:"<<endl;
    a.reset(x,y);
    a.showmove();
    b.showmove();
    /* a调用 reset()函数，设置用户输入数据 */
    cout<<"Object A add B:"<<endl;
    a = a.add(b);
    a.showmove();
    b.showmove();
    /* a调用add()函数，和b相加，返回值赋值给a */
    return 0;
}
Move::Move(double a, double b)
{
    x = a;
    y = b;
}
void Move::showmove() const
{
    cout<<"Current x = "<<x<<", y = "<<y<<endl;
}
Move Move::add(const Move& m)
{
    Move temp;
    temp.x = x + m.x;
    temp.y = y + m.y;
    return temp;
}
void Move::reset(double a, double b)
{
    x = a;
    y = b;
}


