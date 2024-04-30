// 用栈对括号字符串进行有效判定
#include <iostream>
#include <stack>
#include <string>
using namespace std;

bool isEffectiveBracket(string s)
{
	if (s.empty())
	{
		return true;
	}
    stack<char> bracketStack;
	// 如果长度为奇数，那直接就有问题
	if (s.length() % 2 != 0 || s[0] == ')' || s[0] == ']' || s[0] == '}')
	{
		return false;
	}
	// 左括号直接进栈，如果遇到对应右括号，就出栈
	for (int i = 0; i < s.length(); i++)
	{
		// 如果是左括号就进栈
		if (s[i] == '(' || s[i] == '[' || s[i] == '{')
		{
			bracketStack.push(s[i]);
		}
		// 右括号就和栈顶进行匹配
		else
		{
			// 如果此时栈为空，说明不匹配，直接返回
			if (bracketStack.empty())
			{
				return false;
			}
			char temp = bracketStack.top();
			bracketStack.pop();
			if (s[i] == ')' && temp != '(')
			{
				return false;
			}
			if (s[i] == ']' && temp != '[')
			{
				return false;
			}
			if (s[i] == '}' && temp != '{')
			{
				return false;
			}
		}
	}
	if (!bracketStack.empty())
	{
		return false;
	}
	return true;
}

bool isEffectiveBracketPro(string s)
{
	if (s.empty())
	{
		return true;
	}
	stack<char> bracketStack;
	// 如果长度为奇数，那直接就有问题
	if (s.length() % 2 != 0 || s[0] == ')' || s[0] == ']' || s[0] == '}')
	{
		return false;
	}
	// 左括号翻转成右括号进栈，然后右括号来的时候出栈
	for (int i = 0; i < s.size(); i++)
	{
		if (s[i] == '(')
		{
			bracketStack.push(')');
			continue;
		}
		if (s[i] == '[')
		{
			bracketStack.push(']');
			continue;
		}
		if (s[i] == '{')
		{
			bracketStack.push('}');
			continue;
		}
		// 如果是右括号，那就要判断
		// 首先第一种情况，栈这个时候为空，那么说明右括号多出来了
		if (bracketStack.empty())
		{
			return false;
		}
		// 第二种情况，就是不匹配
		if (bracketStack.top() != s[i])
		{
			return false;
		}
		bracketStack.pop();
	}
	// 第三种情况，如果最后栈不为空，说明左括号多了
	if (!bracketStack.empty())
	{
		return false;
	}
	return true;
}

int main()
{
	string s = "()[]{}";
	bool isEffective = isEffectiveBracket(s);
	cout << isEffective << endl;
	s = "()";
	isEffective = isEffectiveBracketPro(s);
	cout << isEffective << endl;
}