#include <iostream>
using namespace std;
// 按 非递减顺序 排序的整数数组 nums，
// 返回 每个数字的平方 组成的新数组，要求也按 非递减顺序 排序。

// 算法：双指针
// 因为得到的新数组的规律就是旧数组的最大值，而旧数组的最大值在两端，因此采用双指针
void doublePointer(int* const nums, int length, int* newNums)
{
    int head = 0;
    int tail = length - 1;
    for (int i = 0; i < length; i++)
    {
        if (nums[head] * nums[head] < nums[tail] * nums[tail])
        {
            newNums[length - 1 - i] = (nums[tail] * nums[tail]);
            tail--;
        }
        else
        {
            newNums[length - 1 - i] = (nums[head] * nums[head]);
            head++;
        }
    }
}
int main()
{
    int length = 5;
    int* nums = new int[length]{ -5, -2, 1, 3, 4 };
    int* newNums = new int[length];
    doublePointer(nums, length, newNums);
    for (int i = 0; i < length; i++)
    {
        cout << newNums[i] << "  ";
    }
    cout << endl;
}

