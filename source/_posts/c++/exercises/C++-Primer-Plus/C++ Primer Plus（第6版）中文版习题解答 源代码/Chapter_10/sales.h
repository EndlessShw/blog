/* sales.h 声明sales类，
 * */
const int QUARTERS = 4;

class Sales{
private:
    double sales[QUARTERS];
    double average;
    double max;
    double min;
public:
    Sales();
    Sales(const double ar[], int n);
    ~Sales(){};
    /* 可以定义空析构函数，也可以使用默认析构函数 */
    void showSales() const;
    /* 打印函数对数据成员无修改操作，应当添加const */
};

