/*第七章：编程练习 6 */
#include <iostream>
using namespace std;

int Fill_array(double[], int);
void Show_array(double[], int);
void Reverse_array(double[], int);
/* 函数的原型声明 */
const int SIZE = 20;
/* 定义数组最大长度 */
int main()
{
    double Array[SIZE];
    int size = Fill_array(Array, SIZE);
    Show_array(Array, size);
    Reverse_array(Array, size);
    Show_array(Array, size);
    Reverse_array(&Array[1], size - 2);
         /*通过控制函数参数的形式实现部分数据的反转 */
    Show_array(Array, size);
    return 0;
}

int Fill_array(double arr[], int size)
{
    int count = 0;
    double temp;
    cout<<"Enter the number seperate by blank, 's' to stop : ";
    cin>>temp;
    while(count < size)
    {
        if(cin.get() == 's')
        {
            return count;
        }else{
            arr[count++] = temp;
            cin>>temp;
        }
    }
    /* 读取数据并输入数组，输入数据时计数，并返回计数值，作为数组长度 */
    return count;
}
void Show_array(double arr[], int size)
{
    cout<<"The array's data: "<<endl;
    for(int i = 0; i < size; i++)
    {
        cout<<arr[i]<<"\t";
    }
    cout<<endl;
    /* 循环打印数组内容，数组长度使用参数size */
}
void Reverse_array(double arr[], int size){
    double temp;
    for(int i = 0; i < size/2; i++)
    {
        temp = arr[i];
        arr[i] = arr[size - i - 1];
        arr[size - i - 1] = temp;
    }
    /* 反转数组，分别从头和尾互换数据 直到数组的中间*/
}
