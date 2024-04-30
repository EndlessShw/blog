// 所有左叶子之和
#include <iostream>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {};
};

void allLeftLeaves(BitNode* node, int& sum, bool isLeft)
{
    // 中
    if (node->left == nullptr && node->right == nullptr && isLeft)
    {
        sum += node->value;
        return;
    }
    if (node->left)
    {
        allLeftLeaves(node->left, sum, true);
    }
    if (node->right)
    {
        allLeftLeaves(node->right, sum, false);
    }
}

int main()
{
    BitNode* head = new BitNode(1);
    head->right = new BitNode(2);
    int sum = 0;
    allLeftLeaves(head, sum, false);
    cout << "左子树的总和为：" << sum << endl;
    BitNode* head2 = new BitNode(3);
    head2->left = new BitNode(9);
    head2->right = new BitNode(20);
    head2->left->left = new BitNode(6);
    head2->left->right = new BitNode(7);
    head2->right->left = new BitNode(15);
    head2->right->right = new BitNode(7);
    sum = 0;
    allLeftLeaves(head2, sum, false);
    cout << "左子树的总和为：" << sum << endl;
}
