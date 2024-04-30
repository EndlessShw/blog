// 二分法
#include <iostream>
using namespace std;

// 题目：给定一个 n 个元素有序的（升序）整型数组 nums 和一个目标值 target，
// 写一个函数搜索 nums 中的 target，如果目标值存在返回下标，否则返回 -1。

int target = 10;
int nums[] = { -1, 2, 5, 7, 10 };

/*
* 二分的区间是 [left, right]，左闭右闭
* @return 返回下标，找不到就返回 -1
*/
int divLeftAndRight(int* nums, int length)
{
	// 定义左边界和右边界
	int left = 0;
	int right = length - 1;
	// 当区间定义为左闭右闭时，left == right 区间是“合法”的，while 循环查找的条件为“合法”条件
	while (left <= right) {
		int middle = (left + right) / 2;
		// 如果中间值大于目标值，说明两点：
		//    1. 中间值不等于目标值
		//    2. 目标值在左区间
		if (nums[middle] > target)
		{
			// 根据第一点，不等于目标值，再加上区间是闭区间，那么区间的右边就不要是 middle 了，
			// 不然会把不相等的值带到下轮循环，边界处理就会有问题
			right = middle - 1;
		}
		else if (nums[middle] < target)
		{
			// 理论同上
			left = middle + 1;
		}
		// 相等就返回下表
		else return middle;
	}
	return -1;
}

/*
* 合法区间为 [left, right)
*/
int divLeft(int* nums, int length)
{
	// 定义左边界和右边界
	int left = 0;
	// 这里有个注意点，当定义为左闭右开时，right 取 length，才能把最后一个元素包含在内
	int right = length;
	// 当区间定义为左闭右开时，left == right 区间是“不合法”的，while 循环查找的条件为“合法”条件
	while (left < right)
	{
		int middle = (left + right) / 2;
		// 左区间
		if (nums[middle] > target)
		{
			// 因为右开，所以 right 取 middle 后，他也不在“合法”的区间内，所以就不用 + 1 了
			right = middle;
		}
		else if (nums[middle] < target)
		{
			// 因为左闭，所以 left 不能取 middle
			left = middle + 1;
		}
		else return middle;
	}
	return -1;
}

int main()
{
	// 获取数组长度
	int n = sizeof(nums) / sizeof(int);
	int pivot = divLeftAndRight(nums, n);
	cout << "下标值为：" << pivot << endl;
	pivot = divLeft(nums, n);
	cout << "下标值为：" << pivot << endl;
}

// 要点总结：
//   1. 一定要统一区间的定义，一般都是 [left, right) 或者 [left, right]。
//      一旦统一了这个区间的定义，那么边界值（left, right）的赋值以及区间“合法”的判断方式，
//      就能随之定义下来
//   2. 区间的定义就是不变量。
//      要在二分查找的过程中，保持不变量，就是在 while 寻找中每一次边界的处理都要坚持根据区间的定义来操作，这就是循环不变量规则。
