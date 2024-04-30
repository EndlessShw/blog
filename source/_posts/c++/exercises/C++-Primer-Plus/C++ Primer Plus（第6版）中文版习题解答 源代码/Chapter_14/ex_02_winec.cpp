#include "winec.h"

template<class T1, class T2>
T1 & Pair<T1,T2>::first()
{
    return a;
}
template<class T1, class T2>
T2 & Pair<T1,T2>::second()
{
    return b;
}

Wine::Wine(const char* l, int y,const int yr[],const int bot[])
: string(l), year(y), PairArray(ArrayInt(yr,y),ArrayInt(bot,y))
{
}
/*私有继承中，基类在初始化列表中初始化 */
Wine::Wine(const char* l, int y) :string(l),year(y),PairArray(ArrayInt(0,0),ArrayInt(0,0))
{
}
/*私有继承中，基类在初始化列表中初始化 */
void Wine::GetBottles() {
    cout << "Enter " << (const string&) (*this) << " data for " << year << " year(s):\n";
    this->first().resize(year);
    this->second().resize(year);
    for (int i = 0; i < year; i++)
    {
        cout << "Enter year: ";
        cin >> this->first()[i];
        cout << "Enter bottles for that year: ";
        cin >> this->second()[i];
    }
}
const string& Wine::Label() const
{
    return (const string&) (*this);
}
/*私有继承中，基类数据成员通过转换访问，即先转换成为基类，再访问其成员 */
int Wine::sum() const
{
    return this->second().sum();
}
void Wine::Show()
{
    cout << "Wine: " << (const string&) (*this) << endl;
    cout << "   Year    Bottles" << endl;
    for (int i = 0; i < year; i++)
    {
        cout << "   " << this->first()[i]
             << "    " << this->second()[i] << endl;
    }
}


