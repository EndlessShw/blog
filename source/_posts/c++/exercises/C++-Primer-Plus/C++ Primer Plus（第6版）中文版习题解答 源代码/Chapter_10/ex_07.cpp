
/*第十章：编程练习 7 */
#include <iostream>
using namespace std;

const int SIZE = 19;
class plorg{
private:
    char name[SIZE];
    int CI;
    /* 两个数据成员，name使用字符数组 */
public:
    plorg(const char st[] = "Plorga", int ci = 50);
    /* 构造函数带参数默认值，缺省CI为50 */
    void reset_ci(int n);
    void print_info() const;
    /* 打印数据信息函数应添加const关键字 */
};

int main()
{
    plorg pl;
    pl.print_info();
    pl.reset_ci(98);
    pl.print_info();
    plorg pm("Stenom",87);
    pm.print_info();
    return 0;
}
plorg::plorg(const char st[], int ci)
{
    strcpy(name,st);
    CI = ci;
}
void plorg::reset_ci(int n)
{
    CI = n;
}
void plorg::print_info() const
{
    cout<<"plorg name: "<<name<<", CI = "<<CI<<endl;
}

