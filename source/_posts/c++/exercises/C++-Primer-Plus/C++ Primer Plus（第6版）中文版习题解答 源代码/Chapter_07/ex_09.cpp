/*第七章：编程练习 9 */
#include <iostream>
using namespace std;
const int SLEN = 30;
struct student{
    char fullname[SLEN];
    char hobby[SLEN];
    int ooplevel;
};
/*
getinfo() has tow arguments: a pointer to the first element of
an array of student structures and an int representing the
number of element of the array. The function solicits and 
stores data about student. It terminates input upon filling
the array or upon encountering a blank line for the student
name. The function returns the actual number of array elements
filled.
*/
int getinfo(student pa[], int n);

//display1() take a student structures as an argukment
//and displays its contents
void display1(student st);

//display2() take the address of student structures as an
//argument and displays the structure's contents
void display2(const student* ps);

//display3() takes the address of the first element of an array
//of student structures and the number of the array elements as
//arguments and displays the cotents of structures
void display3(const student pa[], int n);

int main() {

    cout<<"Enter the class size: ";
    int class_size;
    cin>>class_size;
    while(cin.get() != '\n')
        continue;
    student * ptr_stu = new student[class_size];
    int  entered = getinfo(ptr_stu,class_size);
    for(int i = 0 ; i < class_size; i++)
    {
        display1(ptr_stu[i]);
        display2(&ptr_stu[i]);
    }
    display3(ptr_stu, entered);
    delete[] ptr_stu;
    cout<<"Done\n";
    return 0;
}

int getinfo(student pa[], int n)
{
    int i = 0;
    for( i = 0 ;i< n ; i++)
    {
        cout<<"Enter the info of student name: ";
        cin>>pa[i].fullname;
        cout<<"Enter the info of student hobby: ";
        cin>>pa[i].hobby;
        cout<<"Enter the info of student level: ";
        cin>>pa[i].ooplevel;
        if(!cin)
        {
            cin.clear();
            while(cin.get() != '\n')
                continue;
            cout<<"Bad input. procerss terminated\n";
            break;
        }
    }
    return i;
}
/* getinfo()函数实现学生信息录入功能，通过学生的数组和长度为参数，返回值为录入的信息数量 */

void display1(student st)
{
    cout<<"Student Name: "<<st.fullname<<endl;
    cout<<"Student hobby: "<<st.hobby<<endl;
    cout<<"Stuent level: "<<st.ooplevel<<endl<<endl;
}
/* 以结构变量作为函数参数，打印相关信息 */

void display2(const student* ps)
{
    cout<<"Student Name: "<<ps->fullname<<endl;
    cout<<"Student hobby: "<<ps->hobby<<endl;
    cout<<"Stuent level: "<<ps->ooplevel<<endl<<endl;
}
/* 以指针形式作为函数参数，打印相关信息 */
void display3(const student pa[], int n)
{
    for(int i = 0; i < n; i++)
    {
        cout<<"Student Name: "<<pa[i].fullname<<endl;
        cout<<"Student hobby: "<<pa[i].hobby<<endl;
        cout<<"Stuent level: "<<pa[i].ooplevel<<endl<<endl;
    }
}
/* 以数组形式作为函数参数，打印整个数组的信息 */

