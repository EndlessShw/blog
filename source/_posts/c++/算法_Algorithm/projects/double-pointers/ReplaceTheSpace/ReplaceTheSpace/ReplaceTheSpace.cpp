// 替换字符串中的空格
#include <iostream>
#include <string>
using namespace std;

int getSpaceNum(const string& s)
{
	int count = 0;
	for (int i = 0; i < s.length(); i++)
	{
		if (s[i] == ' ')
		{
			count++;
		}
	}
	return count;
}

string getReplacedStr(string& s)
{
	int spaceNum = getSpaceNum(s);
	int pointer = s.size() - 1;
	s.resize(s.size() + 2 * spaceNum);
	for (int i = s.size() - 1; i >= 0; i--)
	{
		// i 是新长度指针
		// pointer 是旧长度指针
		if (s[pointer] != ' ')
		{
			s[i] = s[pointer];
		}
		else
		{
			s[i] = '0';
			s[i - 1] = '2';
			s[i - 2] = '%';
			i -= 2;
		}
		pointer--;
	}
	return s;
}

int main()
{
	string s = "We are happy.";
	cout << getReplacedStr(s) << endl;
}