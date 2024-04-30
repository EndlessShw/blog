/*第六章：编程练习 9
 * */
#include <iostream>
#include <fstream>
#include <string>
using namespace std;

struct patrons{
    string full_name;
    double fund;
};
/* 捐款人信息的结构体 */
int main() 
{
    ifstream fin;
    string file_name;
    cout<<"Enter the file name: ";
    getline(cin, file_name);
    fin.open(file_name);
    if(!fin.is_open())
    {
        cout<<"Error to open file."<<endl;
        exit(EXIT_FAILURE);
    }
    /* 定义文件对象，打开文件 */
    int patrons_number;
    patrons* ppatrons;
    int id = 0;
    bool empty = true;

    fin>>patrons_number;
    if(patrons_number <= 0)
    {
        exit(EXIT_FAILURE);
    }
    ppatrons = new patrons[patrons_number];
    fin.get();
    /* 读取人数，创建动态数组 */
    while(!fin.eof() && id < patrons_number)
    {
        getline(fin,ppatrons[id].full_name);
        cout<<"Read Name: "<<ppatrons[id].full_name<<endl;
        fin>>ppatrons[id].fund;
        cout<<"Read fund: "<<ppatrons[id].fund<<endl;
        fin.get();
        id++;
    }
    /* 循环读取捐款人信息，也可以使用for循环 */
    fin.close();
    /* 关闭文件 */
    cout<<"Grand Patrons"<<endl;
    for(int i = 0; i < patrons_number; i++)
    {
        if(ppatrons[i].fund >= 10000){
            cout<<ppatrons[i].full_name<<" : "<<ppatrons[i].fund<<endl;
            empty = false;
        }
    }
    if(empty) cout<<"NONE"<<endl;
    empty = false;
    cout<<"Patrons"<<endl;
    for(int i = 0; i < patrons_number; i++)
    {
        if(ppatrons[i].fund < 10000)
        {
            cout<<ppatrons[i].full_name<<" : "<<ppatrons[i].fund<<endl;
        }
    }
    if(empty) cout<<"NONE"<<endl;
    return 0;
}

