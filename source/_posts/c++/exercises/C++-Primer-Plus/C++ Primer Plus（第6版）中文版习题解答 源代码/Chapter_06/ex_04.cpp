/*第六章：编程练习 4
 * */
#include <iostream>
#include <cstring>
using namespace std;

const int strsize = 40;
const int usersize = 40;
//Benevolent Order of Programmer name structure
struct bop{
    char fullname[strsize];    //real name
    char title[strsize];      //job title
    char bopname[strsize]; //secret BOP name
    int preference;       //0 = fullname,1 = title, 2 = bopname
};
bop bop_user[usersize] =
        {{"Wimp Macho","Programmer","MIPS",0},
         {"Raki Rhodes","Junior Programmer","",1},
         {"Celia Laiter","","MIPS",2},
         {"Hoppy Hipman","Analyst Trainee","",1},
         {"Pat Hand","","LOOPY",2},};
/* 定义常量，定义结构，初始化bop数组信息 */
void showmenu();
void print_by_name();
void print_by_pref();
void print_by_title();
void print_by_bopname();
void create_info();
/* 为了保持主程序清晰可读性好，将部分功能代码定义成函数形式 */
int main()
{
    char choice;
   // create_info();
   /* 此处调用create_info()函数可以用户自定义创建数组信息 */
    showmenu();
    cin.get(choice);
    /* 显示菜单，读取用户输入 */
    while(choice != 'q')
    {
        switch(choice)
        {
            case 'a':
                print_by_name();
                break;
            case 'b':
                print_by_title();
                break;
            case 'c':
                print_by_bopname();
                break;
            case 'd':
                print_by_pref();
                break;
            default:
                cout<<"Please enter character a, b, c, d, or q: ";
        }
        /* 通过switch语句对应的函数进行打印显示 */
        cin.get();
        cout<<"Next choice:";
        cin.get(choice);
    }
    /* 将switch语句放置在while循环内，可以实现用户的反复选择各项功能。*/
    cout<<"Bye!"<<endl;
    return 0;
}

void showmenu()
{
    cout<<"a. display by name \t\tb. display by title\n";
    cout<<"c. display by bopname\t\td. display by preference\n";
    cout<<"q. quit\n";
}
/* 显示菜单 */
void print_by_name()
{
    for(int i = 0; i < usersize; i++){
        if(strlen(bop_user[i].fullname) == 0)
            break;
        else
            cout<<bop_user[i].fullname<<endl;
    }
}
/* 通过循环，按名字打印信息 */
void print_by_pref()
{
    for(int i = 0; i < usersize; i++)
    {
        if(strlen(bop_user[i].fullname) == 0)
            break;
        else{
            switch(bop_user[i].preference)
            {
                case 0 :
                    cout<<bop_user[i].fullname<<endl;
                    break;
                case 1:
                    cout<<bop_user[i].title<<endl;
                    break;
                case 2:
                    cout<<bop_user[i].bopname<<endl;
                    break;
            }
        }
    }
}
void print_by_title()
{
    for(int i = 0; i < usersize; i++)
    {
        if(strlen(bop_user[i].fullname) == 0)
            break;
        else
            cout<<bop_user[i].title<<endl;
    }
}
/* 按title打印数组信息 */
void print_by_bopname()
{
    for(int i = 0; i < usersize; i++)
    {
        if(strlen(bop_user[i].fullname) == 0)
            break;
        else
            cout<<bop_user[i].bopname<<endl;
    }
}
/* 按bopname 打印数组信息 */
void create_info()
{
    for(int i = 0; i < usersize; i++)
    {
        cout<<"Enter the user's full name: ";
        cin.getline(bop_user[i].fullname, strsize);
        cout<<"Enter the user's title: ";
        cin.getline(bop_user[i].title, strsize);
        cout<<"Enter the user's bopname: ";
        cin.getline(bop_user[i].bopname, strsize);
        cout<<"Enter the user's preference: ";
        cin>>bop_user[i].preference;
        cout<<"Next...(f for finished):";
        cin.get();
        if(cin.get() == 'f') break;
    }
}
/* 向数组添加bop成员信息 */
