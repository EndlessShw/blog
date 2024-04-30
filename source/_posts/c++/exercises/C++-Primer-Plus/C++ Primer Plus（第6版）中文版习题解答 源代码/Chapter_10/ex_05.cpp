/*第十章：编程练习 5 */

#include <iostream>
#include "stack.h"

using namespace std;
int main()
{
    Stack st; // create an empty stack
    customer cust;
    double sum_payment = 0;
    char select;
    /* 定义变量，对出栈元素的payment求和 */
    cout<<"Select a (add), p (pop) or q(quit) :";
    while(cin.get(select) && select != 'q')
    {
        while(cin.get() != '\n') continue;
        if(select == 'a')
        {
            cout << "Enter a customer's name : ";
            cin.getline(cust.fullname, 35);
            cout << "Enter a customer's payment : ";
            cin >> cust.payment;
            while(cin.get() != '\n') continue;
            st.push(cust);
            cout<<"Item pushed.\n";
        }
        if(select == 'p')
        {
            st.pop(cust);
            sum_payment += cust.payment;
            cout<<"Pop Item's info:\nName : "<<cust.fullname<<endl;
            cout<<"Payment: "<<cust.payment<<endl;
            cout<<"Now, sum of payments: "<<sum_payment<<endl;
        }
        cout<<"Select a (add), p (pop) or q(quit) :";
    }
/* 简单模拟出栈和入栈  */
    cout<<"Bye\n";
    return 0;
}

