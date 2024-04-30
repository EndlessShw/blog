/*第十二章：编程练习 4 */

/*使用题目给定的头文件stack.h */
// stack.cpp -- class declaration for the stack ADT
#include "stack.h"
using namespace std;

Stack::Stack(int n)
{
    pitems  = new Item[n];
    size = n;
    top = 0;
}
Stack::Stack(const Stack & st)
{
    pitems = new Item[st.size];
    /* 复制构造函数，通过参数st复制对象，
     * 数组内数据通过循环复制。*/
    for(int i = 0; i < st.top; i++)
    {
        pitems[i] = st.pitems[i];
    }
    size = st.size;
    top = st.top;
}
Stack::~Stack()
{
    if(pitems != nullptr)
        delete[] pitems;
}
bool Stack::isempty() const
{
    if(top == 0) return true;
    else return false;
}
bool Stack::isfull() const
{
    if(top == size) return true;
    else return false;
}
bool Stack::push(const Item &item) 
{
    if(!isfull())
    {
        pitems[top++] = item;
        return true;
    }else
        {
            return false;
        }
}
bool Stack::pop(Item &item) 
{
    if(!isempty())
    {
        item = pitems[--top];
        return true;
    }else
        {
            return false;
        }
}
Stack& Stack::operator=(const Stack &st)
{
    if (this == &st)
        return *this;
    pitems = new Item[st.size];
    for (int i = 0; i < size; i++)
        pitems[i] = st.pitems[i];
    size = st.size;
    top = st.top;
    return *this;
}

