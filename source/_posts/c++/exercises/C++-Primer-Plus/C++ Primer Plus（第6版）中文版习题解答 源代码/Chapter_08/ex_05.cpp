/*第八章：编程练习 5 */
#include <iostream>
using namespace std;

template<typename T> T max5(T[]);
/* 模板函数声明 */
int main() 
{
    int arr[5] = {1,2,5,4,3};
    double arr_d[5] = {19.6,13,19.8,100.8,98.4};
    cout<<"The Max Element of int array: "<<max5(arr)<<endl;
    cout<<"The Max Element of double array: "<<max5(arr_d)<<endl;
    /* 调用模板函数 统计数组最大值 */
return 0;
}
template<typename T> T max5(T st[])
{
    T max = st[0];
    for(int i = 0; i < 5; i++)
    {
        if(max < st[i]) max = st[i];
    }
    return max;
    /* 通过循环，计算5个元素中的最大值此处题目允许固定数组长度，
     * 否则需要将数组长度通过参数传递。*/
}

