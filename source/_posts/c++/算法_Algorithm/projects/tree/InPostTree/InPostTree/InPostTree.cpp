// 从后序数组和中序数组中构造二叉树
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

void traverse(BitNode* node, vector<int> inOrder, vector<int> postOrder)
{
    if (!node || inOrder.size() == 0 || postOrder.size() == 0)
    {
        return;
    }
    // 首先区间分割的原则是“左闭右闭”
    // 1. 找后序数组的最后一个节点，作为节点元素
    node->val = postOrder.back();
    //cout << node->val << endl;
    postOrder.pop_back();
    // 2. 找到之后，到中序数组中将其分割开
    int prePivot = 0;
    for (int i = 0; i < inOrder.size(); i++)
    {
        if (inOrder[i] == node->val)
        {
            prePivot = i;
            break;
        }
    }
    cout << prePivot << "   " << inOrder.size() << endl;
    // 3. 根据中序数组，后序数组也要切割开，根据数量来看，应该左边的数组大小和中序左边的大小相同
    // 4. 递归回到第一步
    if (prePivot != 0)
    {
        node->left = new BitNode(INT_MAX);
        vector<int> newInOrder(inOrder.begin(), inOrder.begin() + prePivot);
        vector<int> newPostOrder(postOrder.begin(), postOrder.begin() + prePivot);
        traverse(node->left, newInOrder, newPostOrder);
    }
    if (prePivot != inOrder.size() - 1)
    {
        node->right = new BitNode(INT_MAX);
        vector<int> newInOrder(inOrder.begin() + prePivot + 1, inOrder.end());
        vector<int> newPostOrder(postOrder.begin() + prePivot, postOrder.end());
        traverse(node->right, newInOrder, newPostOrder);
    }
}

/**
 * 递归中不改变（包括不用回溯）的变量，可以使用 & 来避免重复创建多个函数形参，
 * 从而节省内存并提高速度，如果想避免在函数中误操作改变，还可以加 const
 * 
 * \param node
 * \param inOrder
 * \param postOrder
 * \param inOrderBegin
 * \param inOrderEnd
 * \param postOrderBegin
 * \param postOrderEnd
 */
void traverse(BitNode* node, 
    const vector<int>& inOrder, 
    const vector<int>& postOrder, 
    int inOrderBegin, 
    int inOrderEnd, 
    int postOrderBegin, 
    int postOrderEnd)
{
    if (!node || inOrder.size() == 0 || postOrder.size() == 0)
    {
        return;
    }
    // 首先区间分割的原则是“左闭右闭”
    // 1. 找后序数组的最后一个节点，作为节点元素
    node->val = postOrder[postOrderEnd];
    //cout << node->val << endl;
    // 注意这里进行了 -- 操作
    postOrderEnd--;
    // 2. 找到之后，到中序数组中将其分割开
    int prePivot = 0;
    for (int i = 0; i <= inOrderEnd - inOrderBegin; i++)
    {
        if (inOrder[i + inOrderBegin] == node->val)
        {
            prePivot = i;
            break;
        }
    }
    cout << prePivot << endl;
    // 3. 根据中序数组，后序数组也要切割开，根据数量来看，应该左边的数组大小和中序左边的大小相同
    // 4. 递归回到第一步
    if (prePivot != 0)
    {
        node->left = new BitNode(INT_MAX);
        // 上一个他取子区间函数是左闭右开的取，下标的话是取得到，这里用的是下标，注意！
        traverse(node->left, inOrder, postOrder, inOrderBegin, inOrderBegin + prePivot - 1, postOrderBegin, postOrderBegin + prePivot - 1);
    }
    if (prePivot != inOrderEnd - inOrderBegin)
    {
        node->right = new BitNode(INT_MAX);
        traverse(node->right, inOrder, postOrder, inOrderBegin + prePivot + 1, inOrderEnd, postOrderBegin + prePivot, postOrderEnd);
    }
}


int main()
{
    vector<int> inOrder = {9, 3, 15, 20, 7};
    vector<int> postOrder = { 9, 15, 7, 20, 3 };
    BitNode* root = new BitNode(INT_MAX);
    traverse(root, inOrder, postOrder);
    traverse(root, inOrder, postOrder, 0, inOrder.size() - 1, 0, postOrder.size() - 1);
}
