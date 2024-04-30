// 用队列实现栈
#include <iostream>
#include <queue>
using namespace std;

class MyStack
{
public:
	MyStack();
	~MyStack();

	void push(int x)
	{
		myQueue.push(x);
	}

	int pop()
	{
		// 整个过程队列的长度不变
		for (int i = 0; i < myQueue.size() - 1; i++)
		{
			myQueue.push(myQueue.front());
			myQueue.pop();
		}
		int result = myQueue.front();
		myQueue.pop();
		return result;
	}

	int top()
	{
		int result = this->pop();
		myQueue.push(result);
		return result;
	}

	

	bool empty()
	{
		return myQueue.empty();
	}


private:
	queue<int> myQueue;
};

MyStack::MyStack()
{
}

MyStack::~MyStack()
{
}

int main()
{
    std::cout << "Hello World!\n";
}
