/*第七章：编程练习 8a */

#include <iostream>
#include <string>
//constant data
const int Season = 4;
const char* Sname[] = {"Spring","Summer","Fall","Winter"};
//function to modify array object

void fill(double arr[], int size);
void show(const double arr[], int size);

int main() 
{

    double expenses[Season];
    fill(expenses, Season);
    show(expenses, Season);
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
}

