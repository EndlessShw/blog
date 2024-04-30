// usebrass2.cpp -- polymorphic example
// compile with brass.cpp
#include <iostream>
#include <string>
#include "dma.h"
const int CLIENTS = 4;

int main()
{
    using std::cin;
    using std::cout;
    using std::endl;

    ABC * p_clients[CLIENTS];
    /* 创建基类ABC 的指针数组 */
    char kind;
    for (int i = 0; i < CLIENTS; i++)
    {
        cout << "Select  1) ABC, 2) baseDMA, 3) lacksDMA, 4) hasDMA : ";

        while (cin >> kind && (kind != '1' && kind != '2' && kind != '3' && kind != '4'))
            cout <<"Enter either 1  2  3 or 4 : ";
        if (kind == '1')
            p_clients[i] = new ABC();
        else if(kind == '2'){
            while (cin.get() != '\n')
                continue;
            char l[40];
            int r;
            cout << "Enter baseDMA's label: ";
            cin.getline(l,40);
            cout << "Enter baseDMA's rating: ";
            cin >> r;
            p_clients[i] = new baseDMA(l,r);
        }
        else if(kind == '3'){
            while (cin.get() != '\n')
                continue;
            char l[40],c[40];
            int r;
            cout << "Enter lacksDMA's label: ";
            cin.getline(l,40);
            cout << "Enter lacksDMA's color: ";
            cin.getline(c,40);
            cout << "Enter lacksDMA's rating: ";
            cin >> r;
            p_clients[i] = new lacksDMA(c,l,r);
        }
        else if(kind == '4'){
            while (cin.get() != '\n')
                continue;
            char l[40],s[40];
            int r;
            cout << "Enter hasDMA's label: ";
            cin.getline(l,40);
            cout << "Enter hasDMA's style: ";
            cin.getline(s,40);
            cout << "Enter hasDMA's rating: ";
            cin >> r;
            p_clients[i] = new hasDMA(s,l,r);
        }

        while (cin.get() != '\n')
            continue;
    }
    cout << endl;
    for (int i = 0; i < CLIENTS; i++)
    {
        p_clients[i]->View();
        cout << endl;
        /* View()作为虚函数，将会依据指针指向的对象类型，匹配相应对象的View()方法。*/
    }

    for (int i = 0; i < CLIENTS; i++)
    {
        delete p_clients[i];  // free memory
    }
    cout << "Done.\n";

    return 0;
}


