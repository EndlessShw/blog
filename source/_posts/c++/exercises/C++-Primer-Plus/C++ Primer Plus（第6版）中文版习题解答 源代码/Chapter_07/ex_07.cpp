/*第七章：编程练习 7 */
#include <iostream>
const int Max = 5;
//function prototypes
double* fill_array(double* begin, double* end);
void show_array(double* begin, double* end);
void revalue(double r, double* begin, double* end);
/* 修改函数原型，参数修改为指针类型 */
int main(int argc, char *argv[]) 
{
    using namespace std;
    double properties[Max];

    double* pend = fill_array(properties, properties+Max);
    show_array(properties, pend);
    if(pend - properties > 0)
    {
        cout<<"Enter revalue factor: ";
        double factor;
        while(!(cin>>factor))
        {
            cin.clear();
            while(cin.get() != '\n')
                continue;
            cout<<"bad input; Please input a number: ";
        }
        revalue(factor, properties, pend);
        show_array(properties, pend);
    }
    cout<<"Done.\n";
    cin.get();
    cin.get();
    return 0;
}

double* fill_array(double* begin, double* end)
{
    using namespace std;
    double temp;
    double* p;
    for(p = begin; p != end; p++){
        cout<<"Enter value #"<< (p - begin) / sizeof(double) + 1 <<":";
        /* 用指针数据的差，除double类型数据的长度，可以得到当前数据排序 */
        cin>>temp;
        if(!cin)
        {
            cin.clear();
            while(cin.get() != '\n')
                continue;
            cout<<"bad input; input process terminated.\n";
            break;
        }else if(temp < 0)
            break;
        *p = temp;
    }
    return p;
}
void show_array(double* begin, double* end)
{
    using namespace std;
    for(double* p = begin; p != end; p++)
    {
        cout<<"Property #"<< (p - begin) / sizeof(double) + 1<<":$";
        cout<<*p<<endl;
    }
    /* 编号显示通过地址差显示。*/
}
void revalue(double r, double* begin, double* end){
    double* p = begin;
    for(double* p = begin; p != end; p++)
    {
        *p = r;
    }
    /* 通过首末指针判断循环是否完成 */
}
