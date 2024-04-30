// 给定一个二叉树和一个目标和，
// 判断该树中是否存在根节点到叶子节点的路径，这条路径上所有节点值相加等于目标和。
#include <iostream>
using namespace std;

struct BitNode
{
	int val;
	BitNode* left;
	BitNode* right;
	BitNode(int value) : val(value), left(nullptr), right(nullptr) {};
};

/**
 * Todo: 也可以返回 bool，在“左右”的时候进行判断，如果满足条件就直接一路向上返回 true（用 number 去减，然后用“回溯”）
 * 
 * \param node
 * \param target
 * \param sum
 * \param hasTarget
 */
void hasTargetFunc(BitNode* node, const int target, int sum, bool& hasTarget)
{
	if (!node)
	{
		return;
	}
	// 中
	sum += node->val;
	// 这里只适用于整数，适当的剪枝了
	if (sum == target && node->left == nullptr && node->right == nullptr)
	{
		hasTarget = true;
		return;
	}
	// 左
	if (node->left != nullptr && node->left->val + sum <= target)
	{
		hasTargetFunc(node->left, target, sum, hasTarget);
	}
	// 右
	if (node->right != nullptr && node->right->val + sum <= target)
	{
		hasTargetFunc(node->right, target, sum, hasTarget);
	}
}

int main()
{
	BitNode* head = new BitNode(5);
	head->left = new BitNode(4);
	head->right = new BitNode(8);
	head->left->left = new BitNode(11);
	head->right->left = new BitNode(13);
	head->right->right = new BitNode(4);
	head->left->left->left = new BitNode(7);
	head->left->left->right = new BitNode(2);
	head->right->right->right = new BitNode(1);

	bool hasTarget = false;
	hasTargetFunc(head, 22, 0, hasTarget);
	cout << "是否有数：" << hasTarget << endl;
	hasTargetFunc(head, 23, 0, hasTarget = 0);
	cout << "是否有数：" << hasTarget << endl;
}