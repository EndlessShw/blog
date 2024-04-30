/*第十六章：编程练习 5 */
#include <iostream>
#include <list>
/* 模板函数的定义 */
template <typename T>
int reduce(T ar[], int n)
{
    std::list<T> ls;
    ls.insert(ls.end(), ar, ar + n);
    /* 创建T类型的list，并将数据复制进入list */
    ls.sort();
    ls.unique();
    /* 排序，删除重复数据 */
    auto pd = ls.begin();
    for (int i = 0; i < ls.size(); i++, pd++)
        ar[i] = *pd;
    return ls.size();
}
int main()
{
    long ar1[5] = {45000, 3400, 45000, 100000, 2500};
    int resize = reduce(ar1, sizeof(ar1)/sizeof(long));
    std::cout << "array1: \n";
    int i;
    for (i = 0; i < resize; i++)
    {
        std::cout << ar1[i] << " ";
    }
    std::string ar2[6] = {"it", "aboard", "it", "zone", "quit", "aa"};
    resize = reduce(ar2, sizeof(ar2)/sizeof(std::string));
    std::cout << "\narray2: \n";
    for (i = 0; i < resize; i++)
    {
        std::cout << ar2[i] << " ";
    }
    return 0;
}

