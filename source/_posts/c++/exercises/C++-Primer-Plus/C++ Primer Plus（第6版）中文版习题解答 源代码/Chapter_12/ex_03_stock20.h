/*第十二章：编程练习 3 */
// stock20.h -- augmented version
#ifndef STOCK20_H_
#define STOCK20_H_
#include <string>

class Stock
{
private:
    char* company;
    /* 使用字符指针，实现动态存储分配。*/
    int shares;
    double share_val;
    double total_val;
    void set_tot() { total_val = shares * share_val; }
public:
    Stock();        // default constructor
    Stock(const char* co, long n = 0, double pr = 0.0);
    ~Stock();       // do-nothing destructor
    void buy(long num, double price);
    void sell(long num, double price);
    void update(double price);
    const Stock & topval(const Stock & s) const;
    friend std::ostream& operator<<(std::ostream& os, const Stock &stock);
    /* 重载运算符<<,实现原show()函数功能。*/
};

#endif
