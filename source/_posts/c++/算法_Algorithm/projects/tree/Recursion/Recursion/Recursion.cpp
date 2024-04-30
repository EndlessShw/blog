#include <iostream>
#include <vector>
using namespace std;

// 二叉树的递归遍历
// 写遍历的思路：
//     1. 确定递归函数的参数和返回值（未必第一次写完）
//     2. 确定终止条件
//     3. 确定单层递归的逻辑

/*
* 二叉树节点
*/
struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(NULL), right(NULL) {}
};

/*
* 前序遍历
* 1. 确定递归方法的参数
* @current 传入的节点
* @nodes 存放遍历时的节点数据
*/
void traverse(BitNode* current, vector<int>& nodes)
{
    // 2. 确定递归的退出条件
    if (current == NULL)
    {
        return;
    }
    // 3. 确定每次递归的运行逻辑
    // 前序遍历是“中左右”
    // 树的遍历中，“中”是要进行访问的(“向中间走”）。
    // “左”和“右”代表向左走和向右走
    // 中间的要将节点的内容存放在数组中（visit）
    nodes.push_back(current->value);
    // 左边的就要先遍历，要把左边的树遍历完
    traverse(current->left, nodes);
    // 左边遍历后，右边也得遍历
    traverse(current->right, nodes);
}

/*
* 后序遍历
* 1. 确定递归方法的参数
* @current 传入的节点
* @nodes 存放遍历时的节点数据
*/
void inverseTraverse(BitNode* current, vector<int>& nodes)
{
    // 2. 确定递归的退出条件
    if (current == NULL)
    {
        return;
    }
    // 3. 确定每次递归的运行逻辑
    traverse(current->left, nodes);
    traverse(current->right, nodes);
    nodes.push_back(current->value);
}

int main()
{
    BitNode headNode(3);
    BitNode leftNode(2);
    BitNode rightNode(4);
    headNode.left = &leftNode;
    headNode.right = &rightNode;
    vector<int> nodes;
    inverseTraverse(&headNode, nodes);
    for (int i = 0; i < nodes.size(); i++)
    {
        cout << nodes[i] << "  ";
    }
    cout << endl;
}

