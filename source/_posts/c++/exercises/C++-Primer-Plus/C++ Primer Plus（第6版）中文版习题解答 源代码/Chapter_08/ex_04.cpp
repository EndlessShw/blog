/*第八章：编程练习 4 */
#include <iostream>
using namespace std;
#include <cstring> 
/* 使用C风格字符串的处理函数，添加头文件cstring */
struct stringy {
    char * str;
    int ct;
};
void show(const string&, int n = 0);
void show(const stringy&,int n = 0);
void set(stringy&, char*);
/* 函数原型声明，函数重载  */
int main()
{
    stringy beany;
    char testing[] = "Reality isn't what it used to be.";

    set(beany, testing);        
    //第一个参数是一个引用，分配空间来保存testing副本，
    //设置beany的str成员指向新块，将testing复制到新块，
    //并设置beany的ct成员
    show(beany); 
    show(beany, 2);
    testing[0] = 'D';
    testing[1] = 'u';
    show(testing);
    show(testing, 3);
    show("Done!");
    /* beany内的new创建的动态存储分配未回收，可在程序结束前使用delete回收
     * 例如：delete beany.str; */
    return 0;
}
void show(const string& st, int n)
{
    if( n == 0) n++;
    for(int i = 0; i < n ; i++ )
    {
        cout<<st<<endl;
    }
}
/* 打印string类型对象信息 */
void show(const stringy& sty, int n)
{
    if( n == 0) n++;
    for(int i = 0; i < n; i++ )
    {
        cout<<sty.str<<endl;
    }
}
/* 打印stringy类型对象信息 */
void set(stringy& sty, char* st)
{
    sty.ct = strlen(st);
    sty.str = new char[sty.ct];
    /* 通过new创建动态存储，此处不考虑delete 回收 */
    strcpy(sty.str,st);
    /* 复制字符串内容 */
}


