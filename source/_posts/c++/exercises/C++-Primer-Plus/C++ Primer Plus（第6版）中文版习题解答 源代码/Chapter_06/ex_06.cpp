/*第六章：编程练习 6
 * */
#include <iostream>
#include <string>
using namespace std;

struct patrons{
    string full_name;
    double fund;
};
/* 定义捐款人基本信息的结构 */
int main()
{
    int patrons_number;
    patrons* ppatrons;
    cout<<"How many patrons? ";
    cin>>patrons_number;
    cin.get();
    /* 读取捐款人名单的长度，多用的一个get() 函数目的是删除缓冲区的换行符 */
    ppatrons = new patrons[patrons_number];
    /* 建立动态数组 */
    int id = 0;
    bool empty = true;
    cout<<"Starting to input patrons' info:"<<endl;
    while(id < patrons_number)
    {
        cout<<"Enter the full name of patrons: ";
        getline(cin, ppatrons[id].full_name);
        cout<<"Enter the fund of "<<ppatrons[id].full_name<<" :";
        cin>>ppatrons[id].fund;
        cin.get();
        id++;
        cout<<"Continue to input, or press (f) to finished.";
        if(cin.get() == 'f') break;
    }
    /* 建立捐款人名单 */
    cout<<"Grand Patrons"<<endl;
    for(int i = 0; i < patrons_number; i++)
    {
        if(ppatrons[i].fund >= 1000){
            cout<<ppatrons[i].full_name<<" : "<<ppatrons[i].fund<<endl;
            empty = false;
        }
    }
    /* 查询Grand Patrons 名单 如果名单empty为true，打印NONE */
    if(empty) cout<<"NONE"<<endl;
    empty = false;
    cout<<"Patrons"<<endl;
    for(int i = 0; i < patrons_number; i++)
    {
        if(ppatrons[i].fund < 1000){
            cout<<ppatrons[i].full_name<<" : "<<ppatrons[i].fund<<endl;
        }
    }
    /* 查询Patrons名单，如果名单empty为true，打印NONE*/
    if(empty) cout<<"NONE"<<endl;
    return 0;
}

