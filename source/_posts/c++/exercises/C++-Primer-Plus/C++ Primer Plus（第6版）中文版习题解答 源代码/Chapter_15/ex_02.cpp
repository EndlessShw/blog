/*第十五章：编程练习 2 */
#include <iostream>
#include <cmath> // or math.h, unix users may need -lm flag
#include <stdexcept>
using namespace std;

/* 修改原程序清单15.10代码，直接将bad_hmean和bad_gmean从logic_error 派生
 * 利用起构造函数初始化waht_arg参数，并通过what()函数打印数据 由于程序比较简单
 * 因此在一个文件内编译实现 */
class bad_hmean : public std::logic_error
{
public:
    bad_hmean(const string what_arg = "HMean, Invalid argument ") : logic_error(what_arg) {}
};
class bad_gmean : public std::logic_error
{
public:
    bad_gmean(const string what_arg = "GMean, Invalid argument ") : logic_error(what_arg) {}
};

double hmean(double a, double b);
double gmean(double a, double b);

int main()
{
    double x, y, z;

    cout << "Enter two numbers: ";
    while (cin >> x >> y)
    {
        try {                  // start of try block
            z = hmean(x,y);
            cout << "Harmonic mean of " << x << " and " << y
                 << " is " << z << endl;
            cout << "Geometric mean of " << x << " and " << y
                 << " is " << gmean(x,y) << endl;
            cout << "Enter next set of numbers <q to quit>: ";
        }// end of try block
        catch (bad_hmean & bg)    // start of catch block
        {
            bg.what();
            cout << "Try again.\n";
            continue;
        }
        catch (bad_gmean & hg)
        {
            cout << hg.what();
            //cout << "Values used: " << hg.v1 << ", "
            //  << hg.v2 << endl;
            cout << "Sorry, you don't get to play any more.\n";
            break;
        } // end of catch block
    }
    cout << "Bye!\n";
    return 0;
}

double hmean(double a, double b)
{
    if (a == -b)
        throw bad_hmean();
    return 2.0 * a * b / (a + b);
}

double gmean(double a, double b)
{
    if (a < 0 || b < 0)
        throw bad_gmean();
    return std::sqrt(a * b);
}
