/*第十一章：编程练习 5 */
#include <iostream>
#include "stonewt.h"

using namespace std;

int main()
{
    Stonewt incognito = 275; // uses constructor to initialize
    cout<<"incognito: "<<incognito<<endl;
    Stonewt wolfe(285.7);    // same as Stonewt wolfe = 285.7;
    cout<<"wolfe: "<<wolfe<<endl;
    Stonewt taft(21, 8);
    cout<<"taft: "<<taft<<endl;


    incognito = 276.8;      // uses constructor for conversion
    cout<<"incognito: "<<incognito<<endl;

    cout<<"wolfe: "<<wolfe*2.3<<endl;
    taft = incognito + wolfe + 200;
    cout<<"taft: "<<taft<<endl;
    wolfe.Set_Style(Stonewt::FLOATPOUNDS);
    wolfe = wolfe*2.3;
    cout<<"wolfe: "<<wolfe*2.3<<endl;
    return 0;
}




