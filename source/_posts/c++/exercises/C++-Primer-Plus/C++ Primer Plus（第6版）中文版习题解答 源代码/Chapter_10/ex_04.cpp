/*第十章：编程练习 4 */
/*main.cpp 仅包含main()函数的主程序 
 * */
#include <iostream>
#include "sales.h"

using namespace std;

int main() {
    double de[QUARTERS] = {12,23,45,67};
    Sales s1(de,QUARTERS);
    Sales s2;
    s1.showSales();
    s2.showSales();
    /* 简单使用类Sale创建对象，并进行基本功能测试 */
    return 0;
}

