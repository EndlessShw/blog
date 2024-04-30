/*第七章：编程练习 1 */
#include <iostream>
using namespace std;

double harmonic(double, double);
/* 函数的原型 */
int main()
{
    double input_num1, input_num2;
    cout<<"Enter the operand( seperate by blank):";
    cin>>input_num1>>input_num2;
    /* 读取系统输入的两个浮点数据 */
    while(input_num1 != 0 || input_num2 != 0){
        /* 函数入口条件是 两个数不同时为 0 */
      cout<<"The "<<input_num1<<" and "<<input_num2;
      cout<<" harmonic mean is "<<harmonic(input_num1,input_num2)<<endl;
        cout<<"Enter the operand( seperate by blank):";
        cin>>input_num1>>input_num2;
    }
    return 0;
}
double harmonic(double x, double y){
   double result = 2.0 * x * y / (x + y);
   return result;
   /* 返回值在算式比较简单时可以直接使用
    * return 2.0 * x * y / (x + y);的形式，
    * 定义变量、计算再返回变量较为繁琐。*/
}
