/* 在原有的代码基础上添加题目要求的部分内容*/
// stack.h
#ifndef STACK_H_
#define STACK_H_

struct customer{
    char fullname[35];
    double payment;
};
/* 添加customer结构的声明 */
typedef customer Item;
/* 修改原Stack内的元素 unsigned long 为customer */

class Stack
{
private:
    enum {MAX = 10};    // constant specific to class
    Item items[MAX];    // holds stack items
    int top;            // index for top stack item
    /* 也可以在栈类内定义Stack使用过的所有元素的payment数据，
     * 但是这样会失去Stack类的通用性。且需要修改构造函数和pop()函数
     * double sum_payment;
     * 因此推荐在主程序田间该变量计算出栈数据的payment和*/
public:
    Stack();
    bool isempty() const;
    bool isfull() const;
    // push() returns false if stack already is full, true otherwise
    bool push(const Item & item);   // add item to stack
    // pop() returns false if stack already is empty, true otherwise
    bool pop(Item & item);          // pop top into item
};
#endif
