/*golf.h golf类的声明文件 */
#include <iostream>

const int Len = 40;
class golf
{
private:
    char fullname[Len];
    int handicap;
public:
    golf();
    golf(const char* name,int hc);
    ~golf(){};
    /* 可以使用默认析构函数，也可以定义空析构函数*/
    void sethandicap(int hc);
    void showgolf() const;
/* 对象信息打印函数，不修改数据成员，应添加const关键字 */
};
