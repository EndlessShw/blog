// pel4-5.cpp
// useempl.cpp -- using the abstr _emp classes
#include <iostream>
#include <fstream>
#include "emp.h"

using namespace std;

const int MAX = 4;  //no more than 10 objects
enum ClassType{ Employee, Manager, Fink, HighFink};

int main(void)
{
    employee em("Trip", "Harris", "Thumper") ;
    cout << em << endl;
    em.ShowAll() ;
    manager ma("Amorphia", "Spindragon", "Nuancer", 5);
    cout << ma << endl;
    ma.ShowAll() ;

    fink fi("Matt", "Oggs", "Oiler", "Juno Barr");
    cout << fi << endl;
    fi.ShowAll ();
    highfink hf(ma, "Curly Kew"); // recruitment?
    hf.ShowAll();
    cout << "Press a key for next phase:\n";
    cin.get();

    ofstream fout("EMP.TXT");
    if(!fout.is_open()){exit(EXIT_FAILURE);}
    cout << "Using an abstr_emp * pointer to write file.\n";
    abstr_emp * tri[MAX] = {&em, &ma, &fi, &hf};
/*
 * 以上为第十四章编程练习五的主程序部分，下面开始修改原有程序，测试本章的文件读写部分。
 * 读写部分使用RTTI方式实现，通过在写入文件时，RTTI判断tri[i]的对象类别，并依照类别写入
 * 标志位，基本形式如下：
 * */
 for (int i = 0; i < MAX; i++)
 {
    if(typeid(*tri[i]) == typeid(employee))
    {
        fout << Employee << endl;
        tri[i]->writeall(fout);
    }
    else if(typeid(*tri[i]) == typeid(manager))
    {
        fout << Manager << endl;
        tri[i]->writeall(fout);
    }
    else if(typeid(*tri[i]) == typeid(fink))
    {
        fout << Fink << endl;
        tri[i]->writeall(fout);
    }
    else if(typeid(*tri[i]) == typeid(highfink))
    {
        fout << HighFink << endl;
        tri[i]->writeall(fout);
    }else{
        fout << -1 << endl;
        tri[i]->writeall(fout);
    };
 }
fout.close();

abstr_emp* pc[MAX];
int classtype;
int i = 0;
ifstream fin("EMP.TXT");
if(!fin.is_open()){exit(EXIT_FAILURE);}
/*文件读取部分，首先读取文件内写入的标志位，并通过标志位比对，判断类型，
 * switch语句内调用不同的对象方法，进行数据恢复。
 * */
    while((fin>>classtype))
    {
        fin.get();
        switch(classtype)
        {
            case Employee:
                pc[i] = new employee;
                pc[i++]->getall(fin);
                break;
            case Manager:
                pc[i] = new manager;
                pc[i++]->getall(fin);
                break;
            case Fink:
                pc[i] = new fink;
                pc[i++]->getall(fin);
                break;
            case HighFink:
                pc[i] = new highfink;
                pc[i++]->getall(fin);
                break;
        }
    }
    for (i = 0; i < MAX; i++) pc[i]->ShowAll();
    fin.close();
    return 0;
}
