// 判断镜像树
#include <iostream>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {};
};

/*
* 思路一：
* 左子树翻转，得到的新树和右子树进行判断（通过对比前序和中序）
*/

/*
* 思路二：
* 左子树“中左右”，右子树“中右左”，两个数组对应位置相等？
* 应该是每一次递归一个点就要比较一次
* 递归可以通过传 2 个参数，以同时进行
*/
void compareBitNode(BitNode* node1, BitNode* node2, bool& isEqual)
{
    if ((node1 == nullptr && node2 != nullptr) || (node1 != nullptr && node2 == nullptr))
    {
        isEqual = false;
        return;
    }
    else if (node1 != nullptr && node2 != nullptr && node1->value != node2->value)
    {
        isEqual = false;
        return;
    }
    else if(node1 == nullptr && node2 == nullptr)
    {
        return;
    }
    //cout << isEqual << endl;
    compareBitNode(node1->left, node2->right, isEqual);
    compareBitNode(node1->right, node2->left, isEqual);
}

/*
* 思路三：
* 后序遍历
*/

int main()
{
    
    //              5
    //           3     3
    //         1   2 2   1
    BitNode* mirrorTree = new BitNode(5);
    mirrorTree->left = new BitNode(3);
    mirrorTree->right = new BitNode(3);
    mirrorTree->left->left = new BitNode(1);
    mirrorTree->left->right = new BitNode(2);
    mirrorTree->right->left = new BitNode(2);
    mirrorTree->right->right = new BitNode(1);
    //mirrorTree->left->left->left = new BitNode(1);
    //              5
    //           4     3
    //         1   2 2   1
    BitNode* tree = new BitNode(5);
    tree->left = new BitNode(4);
    tree->right = new BitNode(3);
    tree->left->left = new BitNode(1);
    tree->left->right = new BitNode(2);
    tree->right->left = new BitNode(2);
    tree->right->right = new BitNode(1);

    bool isEqual = true;
    compareBitNode(mirrorTree->left, mirrorTree->right, isEqual);
    cout << "是否为镜像树：" << isEqual << endl;
    compareBitNode(tree->left, tree->right, isEqual);
    cout << "是否为镜像树：" << isEqual << endl;


}
