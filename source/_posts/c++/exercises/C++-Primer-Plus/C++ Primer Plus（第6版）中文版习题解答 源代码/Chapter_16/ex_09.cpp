/*第十六章：编程练习 9 */
#include <iostream>
#include <ctime>
#include <vector>
#include <list>

using namespace std;
const int LENGTH = 1000000;
int main()
{
    vector<int> vi0;
    /* 定义vector<int>对象 vi0 */
    srand (time(0));
    for(int i = 0; i < LENGTH; i++)
        vi0.push_back(rand()%1000);
    /* 向vi0对象内存入LENGTH个随机数*/
    vector<int> vi(vi0);
    /* 利用 vi0 复制构造vector<int>对象 vi */
    list<int> li(vi0.begin(), vi0.end());
    /* 定义list<int>对象li，将vi0数据复制到li*/
    clock_t time = clock();
    sort(vi.begin(), vi.end());
    time = clock() - time;
    /* vi 排序并计时 */
    cout << "Time used sort by vector.sort(): ";
    cout << (double)(time) / CLOCKS_PER_SEC << " second"<<endl;
    /* 打印vi排序时间 */
    time = clock();
    li.sort();
    time = clock() - time;
    /* 记录list 排序时间 */
    cout << "Time used sort by list.sort(): ";
    cout << (double)(time) / CLOCKS_PER_SEC << " second"<<endl;
    /* 打印li排序时间 */

    li.assign(vi0.begin(), vi0.end());
    /* 重置li对象的数据 */
    time = clock();
    vi.assign(li.begin(), li.end());
    sort(vi.begin(), vi.end());
    li.assign(vi.begin(), vi.end());
    time = clock() - time;
    /* list数据复制到vector，通用排序vector，vector复制回list 三步操作用时记录 */
    cout << "Time used by generic sort : ";
    cout << (double)(time) / CLOCKS_PER_SEC << " second"<< "\n";
    return 0;
}

