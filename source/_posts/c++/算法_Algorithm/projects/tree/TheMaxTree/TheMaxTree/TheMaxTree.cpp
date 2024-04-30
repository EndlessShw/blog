// 根据条件创建最大二叉树
#include <iostream>
#include <vector>
using namespace std;

struct BitNode
{
    int val;
    BitNode* left;
    BitNode* right;
    BitNode(int val) : val(val), left(nullptr), right(nullptr) { };
};

/**
 * 区间采用闭区间.
 * 
 * \param node
 * \param nums
 * \param begin
 * \param end
 */
void maxTree(BitNode* node, const vector<int>& nums, int begin, int end)
{
    if (!node || nums.size() == 0)
    {
        return;
    }
    // 1. 找最大值和所在下标
    // 偏移量
    int maxPivot = 0;
    for (int i = 0; i <= end - begin; i++)
    {
        if (node->val < nums[i + begin])
        {
            node->val = nums[i + begin];
            maxPivot = i;
        }
    }
    // 2. 将其分开
    if (maxPivot != 0)
    {
        node->left = new BitNode(INT_MIN);
        maxTree(node->left, nums, begin, begin + maxPivot - 1);
    }
    if (maxPivot != end - begin)
    {
        node->right = new BitNode(INT_MIN);
        maxTree(node->right, nums, begin + maxPivot + 1, end);
    }
}

int main()
{
    std::cout << "Hello World!\n";
}
