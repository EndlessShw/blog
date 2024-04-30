#include<iostream>
using namespace std;

constexpr auto MAX_SIZE = 10;

struct customer {
	char fullname[35];
	double payment;
};

// 定义顺序栈
struct Stack {
	// 内部的 customer 不被修改
	// 其实不用指针应该也行，可以用 memset 来清空结构体
	const customer* customers[MAX_SIZE];
	// top 指向栈顶元素的下标
	int top = -1;
};

/*
* 入栈
* @stack: 被入的栈，传入引用
* @tempCustomer: 要入栈的元素
*/
void push(Stack& stack, const customer* tempCustomer)
{
	if (stack.top < MAX_SIZE)
	{
		stack.top++;
		stack.customers[stack.top] = tempCustomer;
	}
	else
	{
		cout << "栈已经满了！push 失败！" << endl;
	}
}

/*
* 出栈
* @stack: 被出的栈，传入引用
* @return 返回被出的元素的 payment
*/
int pop(Stack& stack)
{
	if (stack.top != -1) {
		int tempPayment = stack.customers[stack.top]->payment;
		delete stack.customers[stack.top];
		// 这里别忘了 --
		stack.top--;
		return tempPayment;
	}
	else {
		cout << "当前栈是空的，无法 pop!" << endl;
		return 0;
	}
}

int main()
{
	Stack stack = {0};
	double totalPayment = 0;
	customer *customer1 = new customer{ "顾客 1 号", 20.0 };
	customer *customer2 = new customer{ "顾客 2 号", 10.0 };
	push(stack, customer1);
	push(stack, customer2);
	totalPayment += pop(stack);
	totalPayment += pop(stack);
	cout << "totalPayment 为：" << totalPayment << endl;

}