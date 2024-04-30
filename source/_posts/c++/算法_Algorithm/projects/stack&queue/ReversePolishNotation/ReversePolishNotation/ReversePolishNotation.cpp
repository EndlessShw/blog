// 逆波兰表达式求值
#include <iostream>
#include <stack>
#include <vector>
#include <string>
using namespace std;

int operate(const int& op1, const int& op2, string op)
{
	if (op == "*")
	{
		return op1 * op2;
	}
	if (op == "/")
	{
		return op1 / op2;
	}
	if (op == "+")
	{
		return op1 + op2;
	}
	if (op == "-")
	{
		return op1 - op2;
	}
	return 0;
}

int getRPNResult(vector<string>& tokens)
{
	stack<int> opNums;
	for (int i = 0; i < tokens.size(); i++)
	{
		try
		{
			// cpp 的函数，如果不包含数字就会抛出异常
			// 这里这样做是因为用 stoi 时，如果参数不含数字会返回 0，从而影响计算
			int num = stoi(tokens[i]);
			opNums.push(num);
		}
		catch (const std::invalid_argument)
		{
			// 先弹出的是右操作数
			int op1 = opNums.top();
			opNums.pop();
			int op2 = opNums.top();
			opNums.pop();
			opNums.push(operate(op2, op1, tokens[i]));
		}
	}
	return opNums.top();
}

/**
 * 改进：翻转思维 - 先判断四个符号，不是就直接转数字就行
 * 不用考虑 stol 内为字符串时的 0 问题.
 * 不用异常处理，从而加快速度
 * 
 * \param tokens
 * \return 
 */
int getRPNResultPro(vector<string>& tokens)
{
	stack<int> opNums;
	for (int i = 0; i < tokens.size(); i++)
	{
		if (tokens[i] == "+" || tokens[i] == "-" || tokens[i] == "*" || tokens[i] == "/")
		{
			int op1 = opNums.top();
			opNums.pop();
			int op2 = opNums.top();
			opNums.pop();
			opNums.push(operate(op2, op1, tokens[i]));
		}
		else
		{
			int num = stol(tokens[i]);
			opNums.push(num);
		}
	}
	return opNums.top();
}

int main()
{
	vector<string> tokens = { "10", "6", "9", "3", "+", "-11", "*", "/", "*", "17", "+", "5", "+" };
	cout << getRPNResult(tokens) << endl;
}
