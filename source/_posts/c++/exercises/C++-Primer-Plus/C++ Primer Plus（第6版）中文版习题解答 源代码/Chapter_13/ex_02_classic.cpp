/*classic.cpp文件 */
#include <iostream>
#include <cstring>
#include "classic.h"

using namespace std;
Cd::Cd(const char * s1, const char * s2, int n, double x)
{
    performers = new char[strlen(s1) + 1];
    strcpy(performers,s1);
    label = new char[strlen(s2) + 1];
    strcpy(label,s2);
    selections = n;
    playtime = x;
}
/*修改构造函数，实现动态存储 */
Cd::Cd(const Cd & d)
{
    performers = new char[strlen(d.performers) + 1];
    strcpy(performers,d.performers);
    label = new char[strlen(d.label) + 1];
    strcpy(label,d.label);
    selections = d.selections;
    playtime = d.playtime;
}
/*修改复制构造函数，实现动态存储 */
Cd::Cd(){
    performers = nullptr;
    label = nullptr;
    selections = 0;
    playtime = 0.0;
}
/*修改默认构造函数，设置空指针和数据初始化  */
Cd::~Cd(){
    if(performers != nullptr ) delete[] performers;
    if(label != nullptr ) delete[] label;
//    cout<<"Clear Cd's object."<<endl;
}
/*修改析构函数，回收存储单元 */
void Cd::Report()const
{
    if(performers == nullptr || label == nullptr){
        cout<<"Error, empty Object."<<endl;
    }else{
        cout<<"Performers: "<<performers<<endl;
        cout<<"Label: "<<label<<endl;
        cout<<"Selections: "<<selections<<endl;
        cout<<"Playtime: "<<playtime<<endl;
    }
}
Cd & Cd::operator=(const Cd & d){
    if(this == &d)
        return *this;
    performers = new char[strlen(d.performers) + 1];
    strcpy(performers,d.performers);
    label = new char[strlen(d.label) + 1];
    strcpy(label,d.label);
    selections = d.selections;
    playtime = d.playtime;
    return *this;
}


Classic::Classic():Cd()
{
    works = nullptr;
}
Classic::Classic(const Classic& c) :Cd(c)
{
    works = new char[strlen(c.works) + 1];
    strcpy(works,c.works);
}
Classic::Classic(const char* s1,const char* s2,const char* s3,int n,double x) : Cd(s1,s2,n,x)
{
    works = new char[strlen(s3) + 1];
    strcpy(works,s3);
}
/*修改三个构造函数，实现动态存储 */
Classic::~Classic(){
    delete[] works;
//    cout<<"Clear Classic's object."<<endl;
}
/*修改析构函数，回收存储单元 */

void Classic::Report()const
{
    Cd::Report();
    if(works != nullptr )
        cout<<"Works: "<<works<<endl;
}
Classic& Classic::operator=(const Classic& c){
    if(this == &c)
        return *this;
    Cd::operator=(c);
    works = new char[strlen(c.works) + 1];
    strcpy(works,c.works);
    return *this;
}
