/*第十五章：编程练习 3 */
#include <iostream>
#include <cmath> 
using namespace std;

class unexpected_mean : public std::logic_error
{
private:
    double v1;
    double v2;
public:
    unexpected_mean(double a = 0, double b = 0, std::string s = "mean error")
            : v1(a), v2(b), logic_error(s) {}
    virtual void mesg() = 0;
    //virtual ~unexpected_mean() {}
};
/* 首先定义一个基类unexpected_mean ，从logic_error派生，添加两个
 * 数据变量描述错误信息，成员函数mesg()设置虚函数，可以使用默认析构函数 */

class bad_hmean : public unexpected_mean
{
private:
public:
    bad_hmean(double a = 0, double b = 0, std::string s = "HMean")
            : unexpected_mean(a,b,s) {}
    void mesg();
};
/* 定义bad_hmean类 */
class bad_gmean : public unexpected_mean
{
public:
    bad_gmean(double a = 0, double b = 0,std::string s = "GMean")
            : unexpected_mean(a,b,s){}
    void mesg();
};
/* 定义bad_gmean类 */

inline void unexpected_mean::mesg()
{
    cout<<v1<<" "<<v2<<endl;
}


inline void bad_hmean::mesg()
{
    std::cout << "bad_HMean() now!" << std::endl;
    std::cout << what() << "\n";
    std::cout << "Hmean invalid arguments\n";
    unexpected_mean::mesg();
}
/* 定义mesg()函数，输出错误信息。 */

inline void bad_gmean::mesg()
{
    std::cout << "bad_GMean() now!" << std::endl;
    std::cout << what() << "\n";
    std::cout << "Gmean invalid arguments\n";
    unexpected_mean::mesg();
}
/* 定义bad_gmean类，定义mesg()函数，输出错误信息。 */

double hmean(double a, double b);
double gmean(double a, double b);
int main()
{
    double x, y, z;

    cout << "Enter two numbers: ";
    while (cin >> x >> y)
    {
        try {                  // start of try block
            cout << "Harmonic mean of " << x << " and " << y
                 << " is " << hmean(x,y) << endl;
            cout << "Geometric mean of " << x << " and " << y
                 << " is " << gmean(x,y) << endl;
            cout << "Enter next set of numbers <q to quit>: ";
        }// end of try block
        catch (unexpected_mean & bg)    // start of catch block
        {
            if(typeid (bg) == typeid (bad_hmean))
            {
                bad_hmean* ph = dynamic_cast<bad_hmean*> (&bg);
                ph->mesg();
            }else if(typeid (bg) == typeid (bad_gmean))
            {
                bad_gmean* pg = dynamic_cast<bad_gmean*> (&bg);
                pg->mesg();
            }
            cout << "Try again.\n";
            continue;
        }
    }
    cout << "Bye!\n";
    return 0;
}

double hmean(double a, double b)
{
    if (a == -b)
        throw bad_hmean(a,b);
    return 2.0 * a * b / (a + b);
}

double gmean(double a, double b)
{
    if (a < 0 || b < 0)
        throw bad_gmean(a,b);
    return std::sqrt(a * b);
}


