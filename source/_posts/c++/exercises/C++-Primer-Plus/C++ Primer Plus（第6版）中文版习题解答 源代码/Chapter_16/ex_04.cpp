/*第十六章：编程练习 4 */
#include <iostream>
#include <list>

int reduce(long ar[], int n);
int main()
{
    long ar1[5] = {45000, 3400, 45000, 100000, 2500};
    int resize = reduce(ar1, 5);
    std::cout << "array1: \n";
    for (int i = 0; i < resize; i++)
    {
        std::cout << ar1[i] << " ";
    }
    return 0;
}

int reduce(long ar[], int n)
{
    std::list<long> ls;
    ls.insert(ls.end(),ar,ar + n);
    /* 将数组内容复制进list，复制方式添加到末尾 */
    ls.sort();
    ls.unique();
    /* 利用list 的排序和删除重复数据函数 */
    auto pd = ls.begin();
    for (int i = 0; i < ls.size(); i++, pd++)
        ar[i] = *pd;
    /* 将处理完成数据复制回数组，注意list长度改变 */
    return ls.size();
}
