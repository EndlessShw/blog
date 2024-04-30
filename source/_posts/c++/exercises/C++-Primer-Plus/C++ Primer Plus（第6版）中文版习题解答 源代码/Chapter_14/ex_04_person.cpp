/*第十四章：编程练习 4 */
#include <iostream>
#include <cstdlib>
#include <ctime>
#include "perason.h"

Person::Person(string f,string l): fname(f),lname(l)
{
}
void Person::Show() const
{
    cout<<fname<<"."<<lname<<endl;
}
Gunslinger::Gunslinger(string f, string l, int n): Person(f,l), nick(n)
{
}
double Gunslinger::Draw(){
    srand(time(0));
    return rand() % 60;
}
void Gunslinger::Show()const{
    Person::Show();
    cout<<"Nick: "<<nick<<endl;
}
Card PokerPlayer::Draw() const{
    Card temp;
    srand(time(0));
    temp.number = rand() % 52;
    temp.suite =  Card::SUITE (rand() % 4);
    return temp;
}
int main(){
    Person person("Jakey","Slong");
    person.Show();
    /* 测试person对象的创建，和信息打印 */
    Gunslinger gl("Tidy","White",12);
    gl.Show();
    cout<<"Gunslinger's nick is "<<gl.Draw()<<endl;
    /* 测试Gunslinger对象的创建，和信息打印 */
    PokerPlayer pokerplayer;
    pokerplayer.Show();
    /* 测试pockerplayer的默认构造函数 */
}
/* main()函数内进行基本功能测试 */

