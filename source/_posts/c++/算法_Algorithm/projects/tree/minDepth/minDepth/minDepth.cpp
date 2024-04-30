// 求树的最小深度
#include <iostream>
#include <math.h>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {  }
};

/*
* 使用后序遍历获取高度
*/
int getMinDepth(BitNode* node)
{
    if (!node)
    {
        return 0;
    }
    if (node->left == nullptr && node->right != nullptr)
    {
        return getMinDepth(node->right) + 1;
    }
    else if (node->left != nullptr && node->right == nullptr)
    {
        return getMinDepth(node->left) + 1;
    }
    else if (node->left == nullptr && node->right == nullptr)
    {
        return 1;
    }
    else
    {
        return (int)fmin(getMinDepth(node->left), getMinDepth(node->right)) + 1;
    }
}


int result = INT16_MAX;
/*
* 使用前序遍历获取深度
* 前序遍历一般可以不考虑返回值，而且参数可能大于 1
*/
void getMinDepth(BitNode* node, int depth)
{
    if (!node)
    {
        return;
    }
    if (node->left == nullptr && node->right == nullptr)
    {
        result = min(depth, result);
        return;
    }
    if (node->left)
    {
        getMinDepth(node->left, depth + 1);
    }
    if (node->right)
    {
        getMinDepth(node->right, depth + 1);
    }
}

int main()
{
    BitNode* head = new BitNode(1);
    head->right = new BitNode(2);
    head->right->left = new BitNode(4);
    head->right->right = new BitNode(3);
    head->right->right->left = new BitNode(6);
    head->right->right->right = new BitNode(5);
    int minDepth = getMinDepth(head);
    cout << "最小深度为：" << minDepth << endl;
    getMinDepth(head, 1);
    cout << "最小深度为：" << result << endl;
}
