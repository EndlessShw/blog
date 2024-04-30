/*第九章：编程练习 1 */
//golf.cpp
#include <iostream>
#include <cstring>
#include "golf.h"
/* 添加golf头文件 */
using namespace std;

int main(int argc, char *argv[])
{
   golf ann;
   setgolf(ann,"AnnBirdfree",24);

   golf andy;
   setgolf(andy);
   showgolf(ann);
   showgolf(andy);
}

void setgolf(golf& g,const char* name, int hc)
{
   strcpy(g.fullname, name);
   g.handicap = hc;
}
/* setgolf()函数的定义 */

int setgolf(golf& g)
{
   char name[Len];
   int hc;
   cout<<"Please enter the name: ";
   cin.getline(name,Len);

   cout<<"Please enter the handicap: ";
   while(!(cin >> hc))
   {
      cin.clear();
      while(cin.get() != '\n')
         continue;
      cout<<"Please enter the golf's handicap: ";
   }
   /* 判断hc正确输入整型数据 */
   if(name[0] != '\0')
   {
      setgolf(g,name,hc);
      return 1;
   }else{
      return 0;
   }
}
/* 交互方式创建golf对象 */

void handicap(golf& g,int hc)
{
   g.handicap = hc;
}

void showgolf(const golf& g)
{
   cout<<"Name : "<<g.fullname<<", Handicap is "<<g.handicap<<endl;
}


