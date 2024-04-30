/*第十章：编程练习 1 */
#include <iostream>

using namespace std;
class BankAccount{
private:
    string fullname;
    string account;
    double deposit;
public:
    BankAccount();
    BankAccount(const string, const string, float);
    ~BankAccount();
    void init_account(const string, const string, float);
    void print_info() const;
    void save(float);
    void withdraw(float);
};
/*BankAccount类的声明 */

int main()
{
    BankAccount ba("Nik","0001",1200);
    ba.print_info();
    ba.init_account("Nik Swit", "", 1500);
    ba.print_info();
    ba.save(223.5);
    ba.print_info();
    return 0;
}
/*main()函数内简单测试BankAccount类功能 */

BankAccount::BankAccount()
{
    deposit = 0;
}
/*默认构造函数定义 */
BankAccount::BankAccount(string name, string id, float f)
{
    fullname = name;
    account = id;
    deposit = f;
}
/*带参数构造函数定义 */
BankAccount::~BankAccount()
{
    cout<<"All Done!"<<endl;
}
/*析构函数，仅表示对象析构信息 */

void BankAccount::init_account(string name, string id, float f)
{
    cout<<"Initializing Account infomation..."<<endl;
    if(name != "") fullname = name;
    if(id != "") account = id;
    deposit = f;
}
/* 对象初始化 */
void BankAccount::print_info() const
{
    cout<<"The Account info:"<<endl;
    cout<<"Full Name: "<<fullname<<endl;
    cout<<"Account ID: "<<account<<endl;
    cout<<"Deposit: "<<deposit<<endl<<endl;
}
/*打印账号信息  */
void BankAccount::save(float f)
{
    deposit += f;
}
/*存款函数 deposit成员增加值f  */
void BankAccount::withdraw(float f)
{
    deposit -= f;
}
/*取款函数，deposit成员减少值f */


