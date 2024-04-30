/*第十六章：编程练习 7 */
#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
using namespace std;

vector<int> Lotto(int dot, int sdot);
/* 彩票函数声明 返回值是vector<int>对象 */
int main()
{
    vector<int> winners;
    winners = Lotto(51,6);
    vector<int>::iterator pd;
    cout << "winners: \n";
    for (pd = winners.begin(); pd != winners.end(); pd++)
        cout << *pd << " ";
    return 0;
}

vector<int> Lotto(int dot, int sdot)
{
    vector<int> result, temp;
    /* 定义两个vector<int>对象 一个用与生成临时数据 */
    srand(time(0));
    for(int i = 0; i < sdot; i++)
    {
        for(int j = 0; j < dot; j++)
            temp.push_back(rand()%dot);
        random_shuffle(temp.begin(), temp.end());
        /* temp用于存储临时数据，乱序后，取出头元素，转储到result 
         * 从而实现更加优质的随机数据*/
        result.push_back(*temp.begin());
    }
    return result;
}
