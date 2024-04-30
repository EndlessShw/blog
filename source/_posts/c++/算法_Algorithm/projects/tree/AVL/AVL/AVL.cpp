// AVL 树的判断
#include <iostream>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {}
};

/**
 * 后序遍历返回高度.
 * 
 * \param node 每次遍历的节点指针
 * \param isAVL 传入优先为 true
 * \return 子树的高度
 */
int getHeight(const BitNode* node, bool& isAVL)
{
    if (!node)
    {
        return 0;
    }
    // 左
    int leftHeight = getHeight(node->left, isAVL);
    // 右
    int rightHeight = getHeight(node->right, isAVL);
    // 中
    if (abs(rightHeight - leftHeight) > 1)
    {
        isAVL = false;
    }
    return max(leftHeight, rightHeight) + 1;
}

/**
 * 换一种写法.
 * 
 * \param node
 * \return 
 */
int getHeight(const BitNode* node)
{
    if (!node)
    {
        return 0;
    }
    // 左
    int leftHeight = getHeight(node->left);
    if (leftHeight == -1)
    {
        return -1;
    }
    // 右
    int rightHeight = getHeight(node->right);
    if (rightHeight == -1)
    {
        return -1;
    }
    // 中
    if (abs(rightHeight - leftHeight) > 1)
    {
        return -1;
    }
    return max(leftHeight, rightHeight) + 1;
}

int main()
{
    BitNode* head = new BitNode(0);
    head->left = new BitNode(0);
    head->right = new BitNode(0);
    head->left->left = new BitNode(0);
    head->left->right = new BitNode(0);
    head->right->left = new BitNode(0);
    head->right->right = new BitNode(0);
    head->right->right->left = new BitNode(0);
    head->right->right->right = new BitNode(0);
    //head->right->right->right->right = new BitNode(0);
    bool isAVL = true;
    /*getHeight(head, isAVL);*/
    cout << "是二叉树吗：" << isAVL << endl;
}

