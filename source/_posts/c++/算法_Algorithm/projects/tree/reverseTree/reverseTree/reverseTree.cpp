// 翻转二叉树
#include <iostream>
#include <queue>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {};
};

// 用递归写
void reverseTree(BitNode* node)
{
    // 先访问，然后左、右
    // 左指针和右指针的内容颠倒
    BitNode* temp = node->left;
    node->left = node->right;
    node->right = temp;
    temp = nullptr;
    delete temp;
    if (node->left != nullptr)
    {
        reverseTree(node->left);
    }
    if (node->right != nullptr)
    {
        reverseTree(node->right);
    }
}

/*
* 使用中序遍历打印树
*/
void printTree(BitNode* node, vector<int>& result)
{
    if (node->left != nullptr)
    {
        printTree(node->left, result);
    }
    result.push_back(node->value);
    if (node->right != nullptr)
    {
        printTree(node->right, result);
    }
    
}

int main()
{
    //          5                5
    //      4       6 ->      6     4
    //        7   3             3  7
    BitNode* head = new BitNode(5);
    head->left = new BitNode(4);
    head->right = new BitNode(6);
    head->left->right = new BitNode(7);
    head->right->left = new BitNode(3);
    vector<int> result;
    reverseTree(head);
    printTree(head, result);
    for (int i = 0; i < result.size(); i++)
    {
        cout << result[i] << "  ";
    }
    cout << endl;
    

}


