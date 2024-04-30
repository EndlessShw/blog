/*第八章：编程练习 1 */
#include <iostream>
using namespace std;

void loop_print(const char* str, int n = 0);
/* 函数声明，默认参数在声明处定义 */
int main()
{
    loop_print("Hello World!");
    loop_print("Hello World!");
    loop_print("Hello World!", 5);
    return 0;
}
void loop_print(const char* str, int n)
/* 默认参数此处不表示 */
{
   static int func_count = 0;
   /* 静态变量存储函数运行次数 */
   func_count++;
   if(n == 0)
   {
       cout<<"Arguments = 0 ;\n";
      cout<<str<<endl;
      /* 参数为0，则打印一次*/
   }else{
       cout<<"Arguments != 0;\n";
      for(int i = 0;i < func_count; i++)
      {
         cout<<str<<endl;
      }
      /* 参数非0 ，则使用静态变量循环打印*/
   }
}
