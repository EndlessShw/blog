//main.cpp
/* 包含main()函数的 主程序cpp */
#include <iostream>
#include "sales.h"

using namespace std;
using namespace SALES;
/* using预编译器指令，添加SALES名字空间 */
int main()
{
    Sales s1, s2;
    double de[QUARTERS] = {12,23,45,67};
    setSales(s1,de,QUARTERS);
    showSales(s1);
    setSales(s2);
    showSales(s2);
    /* 调用SALES内函数，初始化 s1 s2，并显示内容。*/
    return 0;
}

