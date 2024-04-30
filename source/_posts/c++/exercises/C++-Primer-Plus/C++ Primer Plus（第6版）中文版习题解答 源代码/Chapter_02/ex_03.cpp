/*第二章：编程练习3 */
#include <iostream>
using namespace std;
/* 预编译指令*/

void print_mice(void);
void print_run(void);
/* 函数的声明， 因为要保证在main()函数内
 * 调用函数时，编译器知道该函数的基本信息 */
int main() 
{
/* main()函数 */
    print_mice();
    print_mice();
    print_run();
    print_run();
    /* 函数调用，main()函数称为主调函数，
     * 以上四个函数可以称为被调函数 */
    return 0;
}
/* main()函数结束，注意函数返回值和表示结束的花括号 */

void print_mice(void)
{
    cout<<"Three bline mice"<<endl;
}
void print_run(void)
{
    cout<<"See how they run"<<endl;
}
/* 函数的具体定义，无参数可以使用void或者为空，无返回值必须写void 
 * 定义也可以放置在main()函数前，用定义替换掉声明。
 */
