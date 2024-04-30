/*第十四章：编程练习 3 */
// queuetp.h -- interface for a queue
#ifndef QUEUETP_H_
#define QUEUETP_H_
#include <iostream>
#include <string>
using namespace std;

class Worker   // an abstract base class
{
private:
    std::string fullname;
    long id;
protected:
    void Data() const;
    void Get();
public:
    Worker() : fullname("no one"), id(0L) {}
    Worker(const std::string & s, long n) : fullname(s), id(n) {}
    ~Worker(){};
    void Set();
    void Show() const;
};
/*原有的Worker类保持不变 */

template<class T> class QueueTp
{
private:
// class scope definitions
// Node is a nested structure definition local to this c
    enum {Q_SIZE = 10};
    struct Node{T item; Node* next;};
/* Node节点的结构体，修改成为类型参数类型 */
// private class members
    Node* front; // pointer to front of Queue
    Node* rear; // pointer to rear of Queue
    int items; // current number of items in Queue
    const int qsize; // maximum number of items in Queue
// preemptive definitions to prevent public copying
    QueueTp (const QueueTp & q) : qsize(0) { }
    QueueTp & operator=(const QueueTp & q) { return *this; }
public:
    QueueTp(int qs = Q_SIZE): qsize(qs)
    {
        front = rear = nullptr;
        items = 0;
    }
    ; // create queue with a qs limit
    ~QueueTp()
    {
        Node * temp;
        while(front != nullptr)
        {
            temp = front;
            front = front->next;
            delete temp;
        }
    };
    bool isempty() const;
    bool isfull() const;
    int queuecount () const;
    bool enqueue(const T &item); // add item to end
    bool dequeue (T &item) ; // remove item from front
    /* 入队、出队函数修改其参数类型 */
};
#endif

