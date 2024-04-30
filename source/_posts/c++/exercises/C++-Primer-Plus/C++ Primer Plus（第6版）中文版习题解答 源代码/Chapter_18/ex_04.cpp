/*第十八章：编程练习 4 */
// functor.cpp -- using a functor
#include <iostream>
#include <list>
#include <iterator>
#include <algorithm>

template<class T>  // functor class defines operator()()
class TooBig
{
private:
    T cutoff;
public:
    TooBig(const T & t) : cutoff(t) {}
    bool operator()(const T & v) { return v > cutoff; }
};
/* 函数符定义 */
//void outint(int n) {std::cout << n << " ";}
auto Loutint = [](int n){std::cout << n << " ";};
/* 命名匿名lambda函数Loutin */
int main()
{
    using std::list;
    using std::cout;
    using std::endl;
    using std::for_each;
    using std::remove_if;

    TooBig<int> f100(100); // limit = 100
    int vals[10] = {50, 100, 90, 180, 60, 210, 415, 88, 188, 201};
    list<int> yadayada(vals, vals + 10); // range constructor
    list<int> etcetera(vals, vals + 10);

    // C++0x can use the following instead
//  list<int> yadayada = {50, 100, 90, 180, 60, 210, 415, 88, 188, 201};
//  list<int> etcetera {50, 100, 90, 180, 60, 210, 415, 88, 188, 201};

    cout << "Original lists:\n";
    for_each(yadayada.begin(), yadayada.end(), Loutint);
    /* 调用匿名lambda函数 */
    cout << endl;
    for_each(etcetera.begin(), etcetera.end(), Loutint);
    cout << endl;
    yadayada.remove_if([](int n)->bool{ return n > 100;});  // use a named function object
    etcetera.remove_if([](int n)->bool{ return n > 200;});  // construct a function object
    cout <<"Trimmed lists:\n";
    for_each(yadayada.begin(), yadayada.end(), Loutint);
    cout << endl;
    for_each(etcetera.begin(), etcetera.end(), Loutint);
    cout << endl;
    // std::cin.get();
    return 0;
}


