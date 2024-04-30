/*第八章：编程练习 6 */
#include <iostream>
#include <cstring>

using namespace std;

template<typename T> T maxn(T[], int);
template<> char* maxn<char* >(char*[], int);
/* 模板参数的声明和 模板的具体化声明 */
int main()
{
    int arr[5] = {1,2,5,4,3};
    double arr_d[5] = {19.6,13,19.8,100.8,98.4};
    string ss[] = {"Hello","Hello World!"};

    cout<<"The Max Element of int array: "<<maxn(arr,5)<<endl;
    cout<<"The Max Element of double array: "<<maxn(arr_d,5)<<endl;
    cout<<"The Max Element of string: "<<maxn(ss,2)<<endl;
    return 0;
}
template<typename T> T maxn(T st[], int n)
{
    T max = st[0];
    for(int i = 0; i < n; i++)
    {
        if(max < st[i]) max = st[i];
    }
    return max;
}
/* 模板函数定义 */
template<> char* maxn<char* >(char* sst[], int n)
        {
    int pos = 0;
    for(int i = 0; i < n; i++)
    {
        if(strlen(sst[pos]) < strlen(sst[i]) ) pos = i;
    }
    return sst[pos];
}
/* 模板函数具体化定义*/
