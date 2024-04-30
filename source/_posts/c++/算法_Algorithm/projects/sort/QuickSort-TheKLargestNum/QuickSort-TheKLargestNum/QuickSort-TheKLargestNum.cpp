// 基于快排的算法，找到数组中第 K 个最大元素
#include <iostream>
#include <vector>
using namespace std;

/**
 * 划分函数.
 * 
 * \return 返回枢轴所在位置
 */
int partition(int begin, int end, vector<int>& nums);

/**
 * 一趟快排.
 * 循环不变量，区间的划分采用 [左闭右闭] 的原则
 * 
 * \return 
 */
int quickSort(int begin, int end, vector<int>& nums, int k)
{
	int num1 = 0;
	int num2 = 0;
	if (begin < end)
	{
		// 一次划分，拿到区间枢轴
		int pivot = partition(begin, end, nums);
		if (pivot == nums.size() - k)
		{
			return nums[pivot];
		}
		// 对两个子区间进行划分
		num1 = quickSort(begin, pivot - 1, nums, k);
		num2 = quickSort(pivot + 1, end, nums, k);
	}
	return num1 > num2 ? num1 : num2;
}

int partition(int begin, int end, vector<int>& nums)
{
	// 默认枢轴为首元素
	int pivot = begin;
	int left = begin;
	int right = end;
	// 用于交换的中间变量
	int temp = nums[begin];
	// 循环直到左小右大
	while (left < right)
	{
		// 只要右边的比我大，右边就往左移动
		while (nums[right] > nums[pivot] && left < right)
		{
			right--;
		}
		// 退出循环时，此时右边的值比我小，要进行交换
		temp = nums[right];
		nums[right] = nums[pivot];
		nums[pivot] = temp;
		pivot = right;
		// 只要左边的比我小，左边就往右移动
		while (nums[left] < nums[pivot] && left < right)
		{
			left++;
		}
		// 左边的值比我大，进行交换
		temp = nums[left];
		nums[left] = nums[pivot];
		nums[pivot] = temp;
		pivot = left;
	}
	return pivot;
}

int main()
{
	int k = 2;
	vector<int> nums = { 3, 2, 1, 5, 10, 4 };
	int result = quickSort(0, nums.size() - 1, nums, k);
	cout << result << endl;
	for (int element : nums)
	{
		cout << element << "  ";
	}
	cout << endl;
}

