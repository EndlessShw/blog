/*第十章：编程练习 2 */
#include <iostream>
#include <cstring>
using namespace std;
class Person
{
private:
    static const int LIMIT = 25;
    string lname;                     // Person’s last name
    char fname[LIMIT];             // Person’s first name
public:
    Person() {lname = ""; fname[0] = '\0';}                    // #1
    Person(const string & ln, const char * fn = "Heyyou");      // #2
    // the following methods display lname and fname
    void Show() const;        // firstname lastname format
    void FormalShow() const;  // lastname, firstname format
};

int main()
{
    Person one;                        // use default constructor
    Person two("Smythecraft");         // use #2 with one default argument
    Person three("Dimwiddy", "Sam");   // use #2, no defaults one.Show();
    cout << endl;
    one.FormalShow();
    // etc. for two and three
    two.FormalShow();
    three.FormalShow();
    return 0;
}

Person::Person(const string & ln, const char* fn)
/* 在类外定义类内的成员函数需要使用作用域运算符 */
{
    lname = ln;
    strcpy(fname, fn);
    /* string类型和字符数组类型需要不同的复制数据的方法 */
}
void Person::Show() const
{
    if(lname == "" && fname[0] == '\0')
    {
        cout<<"No Name."<<endl;
    }else
        {
            cout<<"Person Name: "<<fname<<"."<<lname<<endl;
        }
    /* 针对不同情况打印对象信息 */
}
void Person::FormalShow() const
{
    if(lname == "" && fname[0] == '\0')
    {
        cout<<"No Name."<<endl;
    }else{
        cout<<"Person Name: "<<lname<<"."<<fname<<endl;
        /* 先lname形式的格式打印信息 */
    }
}

