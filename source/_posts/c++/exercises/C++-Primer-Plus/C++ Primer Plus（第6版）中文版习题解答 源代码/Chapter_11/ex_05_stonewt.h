/*第十一章：编程练习 5 */
// stonewt.h -- definition for the Stonewt class
#ifndef STONEWT_H_
#define STONEWT_H_
class Stonewt
{
public:
    enum Style{STONE, POUNDS, FLOATPOUNDS};
private:
    enum {Lbs_per_stn = 14};      // pounds per stone
    int stone;                    // whole stones
    double pds_left;              // fractional pounds
    double pounds;                // entire weight in pounds
    Style style;

public:
    Stonewt(double lbs);          // constructor for double pounds
    Stonewt(int stn, double lbs); // constructor for stone, lbs
    Stonewt();                    // default constructor
    ~Stonewt();

    /* 删除show_lbs()和show_stn()函数，使用操作符 << 重载实现相应功能
    void show_lbs() const;        // show weight in pounds format
    void show_stn() const;        // show weight in stone format
    */
    void Set_Style(Style m);
    Stonewt operator+(const Stonewt & s) const;
    Stonewt operator-(const Stonewt & s) const;
    Stonewt operator*(double n) const;
    /* 当前乘法操作符重载在使用成员函数时会限定乘法的两个操作数顺序，double必须在右侧
     * 如果需要实现double数据在左侧，还需要重新定义一个友元函数重载乘法操作符
     * */
    friend std::ostream & operator<<(std::ostream & os, const Stonewt & s);
};
#endif
