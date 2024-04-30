// 删除字符串中的所有相邻的重复项
#include <iostream>
#include <stack>
#include <string>
using namespace std;

string deleteDuplication(string s)
{
	if (s.empty())
	{
		return s;
	}
	stack<char> container;
	container.push(s[0]);
	for (int i = 1; i < s.length(); i++)
	{
		if (container.empty() || s[i] != container.top())
		{
			container.push(s[i]);
		}
		else
		{
			container.pop();
		}
	}
	string result;
	// 这样写效率反而低，不如翻转字符串
	/*while (!container.empty())
	{
		result = container.top() + result;
		container.pop();
	}*/
	while (!container.empty())
	{
		result += container.top();
		container.pop();
	}
	reverse(result.begin(), result.end());
	return result;
}

/**
 * 字符串直接作栈.
 * 
 * \param s
 * \return 
 */
string deleteDuplicationPro(string s)
{
	if (s.empty())
	{
		return s;
	}
	string result;
	result.push_back(s[0]);
	for (int i = 1; i < s.length(); i++)
	{
		if (result.empty() || s[i] != result.back())
		{
			result.push_back(s[i]);
		}
		else
		{
			result.pop_back();
		}
	}
	return result;
}

int main()
{
	string s = "abbaca";
	s = deleteDuplication(s);
	cout << s << endl;
}