#include<iostream>
using namespace std;
//从界面上输入一个字符串（C风格），计算字符串的长度。如果输入的是"abcde"，显示的结果是5。
//其它要求：
//1）把计算字符串长度的功能封装成一个函数。
//2）采用for循环，用数组表示法和临时变量计数。
//3）采用while循环，用指针表示法和临时变量计数。
//4）不用临时变量计数，用递归实现（奇巧淫技）。

constexpr auto STR_LENGTH = 50;

int getLengthByFor(const char* str)
{
	for (int i = 0; i < STR_LENGTH; i++)
	{
		if (str[i] == '\0')
			return i;
	}
	return STR_LENGTH;
}
	
/*
* @str 为常量指针，指向常量的指针。
*/
int getLengthByWhile(const char* str) {
	int count = 0;
	while (*str != '\0')
	{
		count++;
		// 注意指针也要 ++
		str++;
	}
	return count;
}

/*
* 着重注意递归的写法
*/
int getLengthByRecursion(const char* str) {
	// 第一步，写循环结束条件
	if (*str == '\0')
		return 0;
	// 第二步，返回迭代值
	str++;
	int count = getLengthByRecursion(str) + 1;
	return count;
}

int main()
{
	char str[STR_LENGTH];
	cout << "请输入字符串（不超过 50）：" << endl;
	cin >> str;
	cout << "通过 for 循环得到的长度为：" << getLengthByFor(str) << endl;
	cout << "通过 for 循环得到的长度为：" << getLengthByWhile(str) << endl;
	cout << "通过递归得到的长度为：" << getLengthByRecursion(str) << endl;
}
