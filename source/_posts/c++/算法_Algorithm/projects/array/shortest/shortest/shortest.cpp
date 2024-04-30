#include <iostream>
using namespace std;

// 给定一个含有 n 个正整数的数组和一个正整数 s ，找出该数组中满足其和 ≥ s 的长度最小的 连续 子数组，并返回其长度。
// 如果不存在符合条件的子数组，返回 0。

// 算法思想：滑动窗口（双指针）
int doublePointer(const int* nums, const int length, const int target, int& shortest)
{
    int head = 0;
    int tail = 0;
    int total = 0;
    // 区间左闭右闭
    int gap = length + 1;
    // 可以使用 for 循环，这样不仅 tail++ 自动完成，而且 total += nums[tail] 与 tail++ 先后次序不会乱
    // 此时外层的 if 也可以去掉
    while (tail < length)
    {
        if (total < target)
        {
            total += nums[tail];
            tail++;
            if (total > target)
            {
                // 如果再加之后大于等于了，说明目前得到的是暂时的最短值
                while (total >= target)
                {
                    total -= nums[head];
                    head++;
                }
                // 说明最后一次 head++ 前是最短的，那就暂替
                if (tail - head + 2 <= gap)
                {
                    gap = tail - head + 2;
                    shortest = head - 1;
                }
            }
        }
        cout << "tail is " << tail << endl;
    }
    if (total < target)
    {
        return 0;
    }
    return gap;
}

// 算法思想：滑动窗口（双指针）
int doublePointerImproved(const int* nums, const int length, const int target, int& shortest)
{
    int head = 0;
    int tail = 0;
    int total = 0;
    // 区间左闭右闭
    int gap = length + 1;
    // 可以使用 for 循环，这样不仅 tail++ 自动完成，而且 total += nums[tail] 与 tail++ 先后次序不会乱
    // 此时外层的 if 也可以去掉
    for (; tail < length; tail++)
    {
        total += nums[tail];
        while (total > target)
        {
            // 这里的先后逻辑还可以是：
            // 先进行判断赋值，然后再进行 total 和 head 的变化，
            total -= nums[head];
            head++;
            // 这里在超过 2 次以上缩短时，就会重复，因此想要减少次数的话就使用双 if
            // 说明最后一次 head++ 前是最短的，那就暂替
            if (tail - head + 2 <= gap)
            {
                gap = tail - head + 2;
                shortest = head - 1;
            }
        }

    }
    if (total < target)
    {
        return 0;
    }
    return gap;
}

int main()
{
    int target = 7;
    int length = 6;
    int shortest = 0;
    int* nums = new int[length] {2, 3, 1, 2, 4, 3};
    int gap = doublePointerImproved(nums, length, target, shortest);
    if (gap == 0)
    {
        cout << "不符合条件" << endl;
    }
    else
    {
        cout << "最小的集合为：" << endl;
        for (int i = 0; i < gap - 1; i++)
        {
            cout << nums[shortest + i] << "  ";
        }
        cout << endl;
        cout << "最短长度为：" << gap - 1;
    }
}

// 总结：双指针主要用于解决两层循环，O(n^2) 的效率问题，用小空间省大时间。
//       有时双指针需要数组等结构有序，这里需要注意一下。