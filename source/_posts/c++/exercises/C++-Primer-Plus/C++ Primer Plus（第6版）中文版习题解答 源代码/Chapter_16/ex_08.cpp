/*第十六章：编程练习 8 */
#include <iostream>
#include <set>
#include <string>

using namespace std;
int main()
{
    set<string> Mat_set, Pat_set, Guest_set;
    /* 使用集合模板定义三个对象，分别用于存储个人数据和综合数据 */
    cout << "Enter Mat's friends(q to quit): ";
    string name;

    while(getline(cin, name) && name != "q")
    {
        Mat_set.insert(name);
        cout<<name<<" add to Mat's list. (q to quit):";
    }
    /* 添加输入姓名到Mat名单 */
    cout << "\nMat's friends are: \n";
    for(auto pd = Mat_set.begin(); pd != Mat_set.end(); pd++)
        cout << *pd << " ";

    cout << "Enter Pat's friends(q to quit): ";
    while(getline(cin, name) && name != "q")
    {
        Pat_set.insert(name);
        cout<<name<<" add to Pat's list. (q to quit):";
    }
    /* 添加输入姓名到Pat名单 */

    cout << "\nPat's friends are: \n";
    for(auto pd = Pat_set.begin(); pd != Pat_set.end(); pd++)
        cout << *pd << " ";

    Guest_set.insert(Mat_set.begin(),Mat_set.end());
    Guest_set.insert(Pat_set.begin(),Pat_set.end());
    /* 通过inster()函数，合并两个个人名单至总名单 */
    cout << "\nAll friends are: \n";
    for(auto pd = Guest_set.begin(); pd != Guest_set.end(); pd++)
        cout << *pd << " ";
    return 0;
}

