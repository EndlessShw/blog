#include <iostream>
using namespace std;

// 定义结构体
struct st_girl {
	int age;
	int height;
	string bodyShape;
	bool isBeautiful;
} stgirl;

int main()
{
	cout << "请输入年龄：" << endl;
	cin >> stgirl.age;
	cout << "请输入身高：" << endl;
	cin >> stgirl.height;
	cout << "请输入身材（火辣、普通、飞机场）：" << endl;
	cin >> stgirl.bodyShape;

	if (stgirl.age >= 35 && stgirl.age <= 40)
	{
		cout << "她是一个嬷嬷" << endl;
		return;
	}
	if (stgirl.age >= 25 && stgirl.age <= 30)
	{
		cout << "她是一个宫女" << endl;
	}
	else if (stgirl.age >= 18 && stgirl.age < 25)
	{
		// 用全条件判断 + strcmp() 进行字符串比较
	}
}
