/*第十八章：编程练习 3 */
#include<iostream>

long double sum_value() {return 0;};
/* 定义可变参数函数的最后的展开函数 */
template<typename T, typename...Args>
long double sum_value(T value, Args...args)
{
    long double sum = (long double)value + (long double) sum_value(args...);
    return sum;
}
/* 可变参数模板函数 */
int main()
{
    using namespace std;
    cout << sum_value(52, 34, 98, 101)<<endl;
    cout << sum_value('x', 'y', 95, 74, 'Z')<<endl;
    cout << sum_value(0.2, 1e2, 54, 'M','\t')<<endl;
    /* 简单测试可变参数函数，计算参数的和 */
    return 0;
}
