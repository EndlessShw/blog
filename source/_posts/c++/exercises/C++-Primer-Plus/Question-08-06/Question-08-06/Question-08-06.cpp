#include<iostream>
using namespace std;

// 定义一个函数模板
template<typename T>
const T* maxn(const T** elements, const int len)
{
	// 创建哨兵
	int sentinel = 0;
	for (int i = 0; i < len; i++)
	{
		if (*elements[i] > *elements[sentinel])
		{
			sentinel = i;
		}
	}
	// 这里不能将形参的地址传过去
	return elements[sentinel];
}

// 针对字符串的，具体化的函数模板
template<>
const char* maxn(const char** ptrs, const int len)
{
	// 设置哨兵
	int sentinel = 0;
	for (int i = 0; i < len; i++)
	{
		if (strlen(ptrs[sentinel]) < strlen(ptrs[i]))
		{
			sentinel = i;
		}
	}
	return ptrs[sentinel];
}

int main()
{
	int* a1 = new int;
	int* a2 = new int;
	int* a3 = new int;
	*a1 = 4;
	*a2 = 3;
	*a3 = 5;
	const int* a[] = { a1, a2, a3 };
	double* b1 = new double;
	double* b2 = new double;
	double* b3 = new double;
	double* b4 = new double;
	*b1 = 3.5;
	*b2 = 1.45;
	*b3 = 5.52;
	*b4 = 0.31;
	const double* b[] = { b1, b2, b3, b4 };
	char str1[] = "abc";
	char str2[] = "jfioe";
	char str3[] = "cde";
	char str4[] = "nailf";
	const char* strs[] = { str1, str2, str3, str4 };

	const int* maxInt = new int;
	const double* maxDouble = new double;
	const char* maxStr = new char;

	maxInt = maxn<int>(a, sizeof(a) / sizeof(a[0]));
	//cout << maxInt << endl;
	maxDouble = maxn<double>(b, sizeof(b) / sizeof(b[0]));
	maxStr = maxn<char>(strs, 4);

	cout << "int 数组的最大值为：" << *maxInt << endl;
	cout << "double 数组的最大值为：" << *maxDouble << endl;
	cout << "Str 数组的最大值为：" << strlen(maxStr) << endl;
	cout << "Str 数组最长的字符串为：";
	for (int i = 0; i < strlen(maxStr); i++)
	{
		cout << *(maxStr + i);
	}
	cout << endl;
}

// 指向 数组指针（数组内容全是指针） 的指针，本质上是二级指针
// 当然也可以用 *& 来代替 const **