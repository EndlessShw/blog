/*第九章：编程练习 3 */
#include <iostream>
using namespace std;
struct chaff{
    char dross[20];
    int slag;
};

int set_chaff(chaff&, char*, int);
void show_chaff(const chaff&);
/* 函数声明 */

int main()
{
    char buffer[1024];
    /* 创建缓冲区，定位new使用
     * char* buffer =  new char[1024];
     * 使用动态存储创建缓冲区，需要程序结束前使用delete回收存储空间。
     * */
    char st[20];
    int slag, n = 0;
    chaff* pcf = new (buffer) chaff[2];
    /* 使用定位new运算符，在buffer内分配存储单元 */
    cout<<"Enter String to set chaff: ";
    cin.getline(st,20);
    cout<<"Enter a number: ";
    cin>>slag;
    while(strlen(st) > 0)
    {
        cin.get();
        set_chaff(pcf[n++], st, slag);
        if(n >= 2) break;
        /*  简易判断数组输入是否已满 */
        cout<<"Enter String to set chaff: ";
        cin.getline(st,20);
        cout<<"Enter a number: ";
        cin>>slag;
    }
    for(int i = 0; i < 2; i++ )
        show_chaff(pcf[i]);
    return 0;
}
int set_chaff(chaff& cf, char* str, int n)
{
    if(strlen(str) > 0)
    {
        strcpy(cf.dross, str);
        /* 字符数组形式字符串，可以直接复制 */
        cf.slag = n;
        return 1;
    }else{
        return 0;
    }
}
void show_chaff(const chaff& cf)
{
    cout<<"Chaff's Dross: " <<cf.dross<<endl;
    cout<<"Chaff's slag: "<<cf.slag<<endl;
}

