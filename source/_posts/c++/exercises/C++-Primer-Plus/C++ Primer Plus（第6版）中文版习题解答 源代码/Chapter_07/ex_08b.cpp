/*第七章：编程练习 8b */
#include <iostream>
#include <string>
//constant data
const int Season = 4;
const char* Sname[] = {"Spring","Summer","Fall","Winter"};
struct Spend{
    double money[Season];
};
//function to modify array object

void fill(double arr[], int size);
void show(const double arr[], int size);

int main() 
{

    Spend expenses;
    fill(expenses.money, Season);
    show(expenses.money, Season);
    return 0;
}

void fill(double arr[], int size)
{
    using namespace std;
    for(int i = 0; i < size; i++)
    {
        cout<<"Enter "<< Sname[i] <<" expenses: ";
        cin>>arr[i];
    }
/* 通过循环，读取标准输入，填充数据 */
}
void show(const double arr[], int size)
{
    using namespace std;
    double total = 0.0;
    cout<<"\nEXPENSES\n";

    for(int i = 0; i < size; i++)
    {
        cout<< Sname[i] <<":$ "<<arr[i]<<endl;
        total += arr[i];
    }
    cout<<"Total Expenses:$ "<<total<<endl;
/* 通过循环，打印数组信息 */
}

