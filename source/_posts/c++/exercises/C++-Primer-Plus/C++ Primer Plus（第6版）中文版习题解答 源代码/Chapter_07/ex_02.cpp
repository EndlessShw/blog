/*第七章：编程练习 2 */
#include <iostream>
using namespace std;

const int SIZE = 10;
int set_mark(int[],int);
void display_mark(int[],int);
double average_mark(int[],int);
/* 函数原型 */
int main()
{
    int size, golf_mark[SIZE];
    size = set_mark(golf_mark, SIZE);
    /* 调用输入成绩函数，并通过返回值获得成绩数量 */
    cout<<size<<endl;
    display_mark(golf_mark, size);
    cout<<"The average marks is : "<<average_mark(golf_mark, size)<<endl;
    /* 函数调用，打印并计算平均分 */
    return 0;
}
int set_mark(int arr[],int size)
{
    int i = 0;
    do{
        cout<<"Enter the No."<<i+1<<" golf marks: ";
        cin>>arr[i++];
        cin.get();
        cout<<"press enter to continue, or 's' for STOP input : ";
        if(cin.get() == 's'){
            for(;i<size;i++) arr[i] = 0;
            break;
        }
    }while(i < size);
    /* 通过while循环获取输入，但是使用do...while循环会至少需要一次成绩输入，
     * 通常可以使用while循环来实现 0~10次输入 */
    return i;
}
void display_mark(int arr[],int size)
{
    cout<<"The marks is below:"<<endl;
    for(int i = 0; i < size ;i++)
        cout<<arr[i]<<"\t";
    cout<<endl;
 /* 循环打印数组内数据*/
}
double average_mark(int arr[],int size)
{
    int sum = 0;
    for(int i = 0; i < size; i++)
        sum += arr[i];
    return 1.0 * sum / size;
/* 计算数组元素和、取平均值，乘以1.0转换成为浮点数据*/
}

