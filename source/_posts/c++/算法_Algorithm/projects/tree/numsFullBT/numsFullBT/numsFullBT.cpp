// 完全二叉树的点数量
#include <iostream>
#include <math.h>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {  };
};

/*
* 1. 判断左右子树是否为 FBT
* 2. 是的话就套公式
* 3. 不是的话就向下分解遍历
*/
int getNums(BitNode* node)
{
    if (!node)
    {
        return 0;
    }
    int leftDepth = getLeftDepth(node);
    int rightDepth = getRightDepth(node);
    if (leftDepth == rightDepth)
    {
        return pow(2, leftDepth) - 1;
    }
    else
    {
        return getNums(node->left) + getNums(node->right) + 1;
    }
}

int getLeftDepth(BitNode* node)
{
    if (node->left)
    {
        return getLeftDepth(node->left) + 1;
    }
    else
    {
        return 1;
    }
}
int getRightDepth(BitNode* node)
{
    if (node->right)
    {
        return getRightDepth(node->right) + 1;
    }
    else
    {
        return 1;
    }
}

int main()
{
    
}

