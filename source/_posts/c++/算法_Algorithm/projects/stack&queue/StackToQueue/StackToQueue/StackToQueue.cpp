// 用 stl 的栈实现队列
#include <iostream>
#include <stack>
using namespace std;

class MyQueue
{
public:
	MyQueue();
	~MyQueue();

    void push(int x) {
        // 如果主栈为空
        if (stack1.size() == 0 && stack2.size() != 0)
        {
            // 注意这里的 stack2.size() 是变化的，因此不能直接在 for 里面用
            int round = stack2.size();
            for (int i = 0; i < round; i++)
            {
                stack1.push(stack2.top());
                stack2.pop();
            }
        }
        stack1.push(x);
    }

    int pop() {
        int result = this->peek();
        stack2.pop();
        return result;
    }

    int peek() {
        if (stack1.size() != 0)
        {
            int round = stack1.size();
            for (int i = 0; i < round; i++)
            {
                stack2.push(stack1.top());
                stack1.pop();
            }   
        }
        return stack2.top();
    }

    bool empty() {
        if (stack1.empty() && stack2.empty())
        {
            return true;
        }
        return false;
    }
private:
    // 主栈
    stack<int> stack1;
    // 副栈
    stack<int> stack2;
};

MyQueue::MyQueue()
{
}

MyQueue::~MyQueue()
{
}

int main()
{
    MyQueue* obj = new MyQueue();
    obj->push(1);
    obj->push(2);
    int param_3 = obj->peek();
    int param_2 = obj->pop();
    bool param_4 = obj->empty();
    cout << param_2 << endl;
    cout << param_3 << endl;
}
