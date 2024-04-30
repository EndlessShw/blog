/*第五章：编程练习 7
 * */
#include <iostream>
#include <string>
using namespace std;
struct car_info
{
    string manufacturer;
    int date;
};
/* 定义汽车信息的结构 */
int main()
{
    int car_number;
    car_info* pcar;
    cout<<"How many cars do you wish to catalog? ";
    cin>>car_number;
    cin.get();
    pcar = new car_info[car_number];
    /* 通过用户输入数量，动态创建汽车信息的数组 */
    for(int i = 0; i < car_number; i++)
    {
        cout<<"Car #"<<i+1<<":"<<endl;
        cout<<"Please enter the maker: ";
        getline(cin, pcar[i].manufacturer);
        cout<<"Please enter the year made: ";
        cin>>pcar[i].date;
        cin.get();
    }
    /* 通过循环输入汽车信息 */
    cout<<"Here is you collection:"<<endl;

    for(int i = 0; i < car_number; i++)
    {
        cout<<pcar[i].date<<" "<<pcar[i].manufacturer<<endl;
    }
    /* 打印汽车的基本信息*/
    return 0;
}

