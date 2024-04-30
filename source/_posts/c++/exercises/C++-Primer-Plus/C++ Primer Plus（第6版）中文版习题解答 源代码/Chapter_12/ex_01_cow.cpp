//Cow.cpp
#include "cow.h"
using namespace std;

Cow::Cow()
{
    name[0] = '\0';
    hobby = nullptr;
    /* hobby也初始化为一个空字符串，即
     * hobby = new char[1];
     * hobby[0] = '/0';
     * 这样在部分函数内可以省略空指针的判断。
     * */
    weight = 0.0;
}

Cow::Cow(const char * nm, const char * ho, double wt)
{
    strncpy(name, nm, 20);
    if(strlen(nm) >= 20) name[19] = '\0';
    else name[strlen(nm)] = '\0';
    /* 使用strncpy()函数，通过第三个参数，限制输入字符长度，
     * 并设置字符串末尾为空字符。*/
    hobby = new char[strlen(ho)+1];
    strcpy(hobby, ho);
    /* 使用new创建动态存储，可以直接进行数据复制*/
    weight = wt;
}

Cow::Cow(const Cow & c)
{
    strcpy(name, c.name);
    hobby = new char[strlen(c.hobby)+1];
    strcpy(hobby, c.hobby);
    weight = c.weight;
}

Cow::~Cow()
{
    delete[] hobby;
}

Cow & Cow::operator=(const Cow & c)
{
    if (this == &c)
        return *this;
    if(hobby != nullptr) delete[] hobby;
    hobby = new char[strlen(c.hobby)+1];
    /* hobby使用new进行动态存储分配时，必须确保原指针为空。否则会产生
     * 内存泄漏。*/
    strcpy(name, c.name);
    strcpy(hobby, c.hobby);
    weight = c.weight;
    return *this;
}

void Cow::ShowCow() const
{
    if(hobby == nullptr){
        /*如果为空指针，则：
         * cout<<hobby；
         * 无法通过该指针寻址到字符串，会出现运行时错误，*/
        cout<<"This Cow's info is Empty!"<<endl;
        return;
    }else{
        cout << "This is Information of COW."<<endl;
        cout << "Name: " << name << endl;
        cout << "Hobby: " << hobby << endl;
        cout << "Weight: " << weight << endl;
    }
}

