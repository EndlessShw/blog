/*第八章：编程练习 7 */
// tempover.cpp --- template overloading
#include <iostream>

template <typename T>// template A
void ShowArray(T arr[], int n);

template <typename T>// template B
void ShowArray(T* arr[], int n);
/* 原ShowArray()模版函数声明 */
template<typename T> T SumArray(T arr[], int n);
template<typename T> T SumArray(T* arr[], int n);
/* 新添加模板函数 */
struct debts
{
    char name[50];
    double amount;
};

int main()
{
    using namespace std;
    int things[6] = {13, 31, 103, 301, 310, 130};
    struct debts mr_E[3] = {
            {"Ima Wolfe", 2400.0},
            {"Ura Foxe", 1300.0},
            {"Iby Stout", 1800.0}
    };
    double * pd[3];
    // set pointers to the amount members of the structures in mr_E
    for (int i = 0; i < 3; i++)
        pd[i] = &mr_E[i].amount;
    cout << "Listing Mr. E's counts of things:\n";
// things is an array of int
    ShowArray(things, 6);  // uses template A
    cout << "Listing Mr. E's debts:\n";
// pd is an array of pointers to double
    ShowArray(pd, 3);     // uses template B (more specialized)

    cout<<"The sum of things: "<<SumArray(things, 6)<<endl;
    cout<<"The sum of pd: "<<SumArray(pd, 3)<<endl;
/* 调用模板函数，计算数组和，并打印数组和 */
    return 0;
}
template <typename T>
void ShowArray(T arr[], int n)
{
    using namespace std;
    cout << "template A\n";
    for (int i = 0; i < n; i++)
        cout << arr[i] << ' ';
    cout << endl;
}
template <typename T>
void ShowArray(T * arr[], int n)
{
    using namespace std;
    cout << "template B\n";
    for (int i = 0; i < n; i++)
        cout << *arr[i] << ' ';
    cout << endl;
}
template<typename T>
T SumArray(T arr[], int n)
{
    using namespace std;
    T sum = 0;
    /* T为模板参数输入类型，0 为int类型，通常可以类型转换，特定情况下可以使用
     * T sum = arr[0] - arr[0];
     * 来标识此处未定类型的初始化 */
    for (int i = 0; i < n; i++)
        sum += arr[i];
    return sum;
}

template<typename T>
T SumArray(T* arr[], int n)
{
    using namespace std;
    T sum = *arr[0] - *arr[0];
    for (int i = 0; i < n; i++)
        sum += *arr[i];
    return sum;

}


