// 找到最左下的叶子（优先下，然后左）
#include <iostream>
#include <queue>
using namespace std;

struct BitNode
{
	int val;
	BitNode* left;
	BitNode* right;
	BitNode(int value) : val(value), left(nullptr), right(nullptr) {};
};

void getNorthWest(const BitNode* node, int& number, int depth, int& depthest)
{
	// 中
	if (depth > depthest)
	{
		depthest = depth;
		number = node->val;
	}
	// 左
	if (node->left)
	{
		getNorthWest(node->left, number, depth + 1, depthest);
	}
	// 右
	if (node->right)
	{
		getNorthWest(node->right, number, depth + 1, depthest);
	}
}

/**
 * 使用层序遍历.
 * 
 * \param head
 * \return 
 */
int getNorthWest(BitNode* head)
{
	if (!head)
	{
		return 0;
	}
	int number = head->val;
	queue<BitNode*> nodeQueue;
	nodeQueue.push(head);
	while (!nodeQueue.empty())
	{
		number = nodeQueue.front()->val;
		int round = nodeQueue.size();
		for (int i = 0; i < round; i++)
		{
			BitNode* node = nodeQueue.front();
			nodeQueue.pop();
			if (node->left)
			{
				nodeQueue.push(node->left);
			}
			if (node->right)
			{
				nodeQueue.push(node->right);
			}
		}
	}
	return number;
}

int main()
{
	BitNode* head = new BitNode(1);
	head->left = new BitNode(2);
	head->right = new BitNode(3);
	head->left->left = new BitNode(4);
	head->right->left = new BitNode(5);
	head->right->right = new BitNode(6);
	head->right->left->left = new BitNode(7);

	int depthest = 0;
	int number = head->val;
	getNorthWest(head, number, 0, depthest);
	cout << "最下左的值为：" << number << endl;
	cout << "最下左的值为：" << getNorthWest(head) << endl;
}


