/*第十四章：编程练习 3 */
#include "queuetp.h"

void Worker::Set()
{
    cout<<"Enter worker's name: ";
    getline(cin,fullname);
    cout<<"Enter worker's ID: ";
    cin>>id;
    while(cin.get()!='\n')
        continue;
}
void Worker::Show() const
{
    cout<<"Name: "<<fullname<<endl;
    cout<<"Employee ID: "<<id<<endl;
}
/* Worker类的成员函数实现 */

template <class T>
QueueTp <T>::QueueTp(int qs):qsize(qs)
/* 模板类的构造函数 */
{
   front = rear = nullptr;
   items = 0;
}

template <class T>
QueueTp<T>::~QueueTp()
/* 模板类的析构函数 */
{
   Node * temp;
   while(front != nullptr)
   {
      temp = front;
      front = front->next;
      delete temp;
   }
}

template <class T>
bool QueueTp<T>::isempty() const
{
    return items == 0;
}

template <class T>
bool QueueTp<T>::isfull() const
{
    return items == qsize;
}

template <class T>
int QueueTp<T>::queuecount() const
{
    return items;
}

template <class T>
bool QueueTp<T>::enqueue(const T &item)
{
    if(isfull())
        return false;
    Node * temp = new Node;
    temp->item = item;
    temp->next = nullptr;
    items++;
    if(front == nullptr)
        front = temp;
    else
        rear->next = temp;
    rear = temp;
    return true;
}
/* 模板类入队函数定义 */

template <class T>
bool QueueTp<T>::dequeue(T &item)
{
    if(isempty())
        return false;
    item = front->item;
    items--;
    Node * temp = front;
    front = front->next;
    delete temp;
    if(items == 0)
        rear = nullptr;
    return true;
}
/* 模板类出队函数定义 */

