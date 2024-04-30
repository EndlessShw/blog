#include <iostream>
#include <vector>
using namespace std;

// 题目：给你一个数组 nums 和一个值 val，你需要“原地”移除所有数值等于 val 的元素，
// 并返回移除后数组的新长度。
// 不要使用额外的数组空间，仅使用 O(1) 额外空间并原地修改输入数组。
// 例如：给定 nums = [0,1,2,2,3,0,4,2], val = 2, 函数应该返回新的长度 5, 并且 nums 中的前五个元素为 0, 1, 3, 0, 4。

// 算法一：暴力破解（用 vector 的库函数）
void bruteForce(vector<int> &nums, const int val)
{
    for (int i = 0; i < nums.size(); i++)
    {
        if (nums[i] == val)
        {
            // 删去一个元素，并讲所有元素向前挪一位，size-- 但 capacity 不变
            nums.erase(nums.begin() + i);
            i--;
        }
    }
}
// 算法二：暴力破解（数组）
int* bruteForce(int* nums, const int val, int& length)
{
    for (int i = 0; i < length; i++)
    {
        if (nums[i] == val)
        {
            for (int j = 0; j < length - i; j++)
            {
                nums[i + j] = nums[i + j + 1];
            }
            i--; length--;
        }
    }
    return nums;
}

// 算法三：双指针法
int* doublePointer(int* nums, const int val, int& length)
{
    // slow 指针指向被删除元素，相当于是新数列元素的所在位置
    int slowPointer = 0;
    int oldLength = length;
    // fast 指针指向删除元素后新数列的元素
    for (int fastPointer = 0; fastPointer < oldLength; fastPointer++)
    {
        if (nums[fastPointer] != val)
        {
            // 只要值不相同就覆盖
            nums[slowPointer] = nums[fastPointer];
            slowPointer++;
        }
    }
    // 最终 slowPointer 指向新数组的后一个元素
    length = slowPointer;
    return nums;
}
int main()
{
    vector<int> nums = { 0, 1, 2, 2, 3, 0, 4, 2 };
    int val = 2;
    bruteForce(nums, val);
    cout << "nums 为：" << "    ";
    for (int i = 0; i < nums.size(); i++)
    {
        cout << nums[i] << "    ";
    }
    cout << endl << endl;

    int length = 8;
    int* nums2 = new int[length] { 0, 1, 2, 2, 3, 0, 4, 2 };
    int* nums2_ = bruteForce(nums2, val, length);
    cout << "长度为：" << length << endl;
    cout << "nums2 为：" << "    ";
    for (int i = 0; i < length; i++)
    {
        cout << nums2_[i] << "    ";
    }
    cout << endl << endl;
    
    int length2 = 8;
    int* nums3 = new int[length2] { 0, 1, 2, 2, 3, 0, 4, 2 };
    int* nums3_ = doublePointer(nums3, val, length2);
    cout << "长度为：" << length2 << endl;
    cout << "nums3 为：" << "    ";
    for (int i = 0; i < length2; i++)
    {
        cout << nums3_[i] << "    ";
    }
    cout << endl;

}

