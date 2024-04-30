// stock20.cpp -- augmented version
#include <iostream>
#include "stock20.h"
using namespace std;
// constructors
Stock::Stock()        // default constructor
{
    company = new char[8];
    strcpy(company, "no name");
    /* 缺省构造函数使用字符串"no name"初始化company，
     * 因此先使用new动态存储分配8个字符*/
    shares = 0;
    share_val = 0.0;
    total_val = 0.0;
}

Stock::Stock(const char* co, long n, double pr)
{
    company = new char[strlen(co)+1];
    strcpy(company, co);
    /*依据参数co 动态分配company 内存。*/
    if (n < 0)
    {
        std::cout << "Number of shares can't be negative; "
                  << company << " shares set to 0.\n";
        shares = 0;
    }
    else
        shares = n;
    share_val = pr;
    set_tot();
}

// class destructor
Stock::~Stock()        // quiet class destructor
{
    if(company != nullptr) delete[] company;
    /* 析构函数需要回收company 内存。*/
}

// other methods
void Stock::buy(long num, double price)
{
    if (num < 0)
    {
        std::cout << "Number of shares purchased can't be negative. "
                  << "Transaction is aborted.\n";
    }
    else
    {
        shares += num;
        share_val = price;
        set_tot();
    }
}

void Stock::sell(long num, double price)
{
    using std::cout;
    if (num < 0)
    {
        cout << "Number of shares sold can't be negative. "
             << "Transaction is aborted.\n";
    }
    else if (num > shares)
    {
        cout << "You can't sell more than you have! "
             << "Transaction is aborted.\n";
    }
    else
    {
        shares -= num;
        share_val = price;
        set_tot();
    }
}

void Stock::update(double price)
{
    share_val = price;
    set_tot();
}

ostream& operator<<(ostream& os, const Stock &stock)
{
    /* 使用原show()函数的代码，需要修改其输出语句std::cout为参数的os对象。*/
    using std::ios_base;
    // set format to #.###
    ios_base::fmtflags orig =
            os.setf(ios_base::fixed, ios_base::floatfield);
    std::streamsize prec = os.precision(3);

    os << "Company: " << stock.company
         << "  Shares: " << stock.shares << '\n';
    os << "  Share Price: $" << stock.share_val;
    // set format to #.##
    os.precision(2);
    os << "  Total Worth: $" << stock.total_val << '\n';

    // restore original format
    os.setf(orig, ios_base::floatfield);
    os.precision(prec);
    return os;
}

const Stock & Stock::topval(const Stock & s) const
{
    if (s.total_val > total_val)
        return s;
    else
        return *this;
}


