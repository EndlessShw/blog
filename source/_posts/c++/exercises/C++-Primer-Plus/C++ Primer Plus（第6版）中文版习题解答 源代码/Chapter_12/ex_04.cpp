/*第十二章：编程练习 4 */
#include <iostream>
#include "stack.h"
using namespace std;

const int MAX = 5;
int main() {
    Stack st(MAX); // create an empty stack
    Item item;
    for(int i = 0 ; i < MAX ; i++)
    {
        cout << "Enter a unsigned long number : ";
        cin >> item;
        while(cin.get() != '\n') continue;
        st.push(item);
        cout<<"Item pushed.\n";
    }
    Stack st_new(st);
    for(int i = 0 ; i < MAX ; i++)
    {
        st_new.pop(item);
        cout<<"Item poped: "<<item<<endl;;
    }
    /* 简单模拟出栈和入栈 */
    cout << "Bye\n";
    return 0;
}

