/*第十章：编程练习 8 */
#include <iostream>
#include "list.h"
using namespace std;

int main()
{
    List list;
    Item item = 0;
    cout<<"Enter the unsigned long number: ";
    cin>>item;
    while(item != 0)
    {
        cin.get();
        list.add(item);
        cout<<"Enter the unsigned long number: ";
        cin>>item;
    }
    cout<<"Now end of add element, start to visit:"<<endl;
    list.visit(visit_Item);
    return 0;
}


