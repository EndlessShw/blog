#include <iostream>
#include <vector>
#include <stack>
#include <algorithm>
using namespace std;

// 用非递归遍历树
// 系统本质上在实现递归时用的是栈，因此可以使用栈模拟递归操作。
// 用栈实现非递归本质就是模拟计算机实现递归

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(NULL), right(NULL) {}
};

/*
* 非递归还是要记住一点，中间节点是“访问”（向中间走），左右节点是向下走。
* 前序非递归遍历
*/
vector<int> preorderedTraverse(BitNode head)
{
    // 这个栈要求出栈后的顺序为遍历的顺序
    // 同时，出栈就代表着要访问节点（因为前序递归访问的顺序同遍历的顺序）
    stack<BitNode> nodeStack;
    vector<int> order;
    // 1. 头节点入栈
    // 需要注意一下，如果栈存的是 BitNode*，这里才能对 head 进行判断（此时 head 为指针）
    nodeStack.push(head);
    while (!nodeStack.empty())
    {
        // 2. 前序遍历，“中”出栈，访问
        BitNode node = nodeStack.top();
        order.push_back(node.value);
        nodeStack.pop();
        // 3. 右孩子入栈
        if (node.right != NULL)
        {
            nodeStack.push(*node.right);
        }
        // 4. 左孩子入栈
        if (node.left != NULL)
        {
            nodeStack.push(*node.left);
        }
        // 5. 回到第二点
        // 6. 结束条件：栈不为空
    }
    return order;
}

/*
* 后续遍历的思路：
*     在前序遍历的基础上，中左右 -> 中右左 -> 左右中
*/
vector<int> afterOrderedTraverse(BitNode head)
{
    stack<BitNode> nodeStack;
    vector<int> order;
    // 1. 头节点入栈
    // 需要注意一下，如果栈存的是 BitNode*，这里才能对 head 进行判断（此时 head 为指针）
    nodeStack.push(head);
    while (!nodeStack.empty())
    {
        BitNode node = nodeStack.top();
        order.push_back(node.value);
        nodeStack.pop();
        // 这里就是将先左后右进栈，实现中右左
        // 注意这里空节点是不入栈的，要和中序遍历区分开
        if (node.left != NULL)
        {
            nodeStack.push(*node.left);
        }
        if (node.right != NULL)
        {
            nodeStack.push(*node.right);
        }  
    }
    // 最后将数列反转，实现左右中
    reverse(order.begin(), order.end());
    return order;
}

/*
* 中序遍历的特殊性：
*     1. 二叉树的遍历中，共分为两步：访问节点和处理节点。
*     2. 对于前序和后续遍历：
*            前序 - 先访问后遍历
*            后序 - 先遍历后访问
*     3. 而中序遍历，他是遍历-访问-遍历。因此中序遍历特殊
* 详细来讲，树的遍历实际上分为两个阶段：遍历和访问。
* 遍历时，永远都是从左走，走到头回头，再走到右边，再回头。一直重复，直到踩过每一个点。
* 而在这期间，什么是否访问决定了遍历的顺序类型。每个节点应该都会被踩点 3 次，对于缺少孩子的节点，其可能会有“原地踏步”的情况。
* 先序遍历就是访问的顺序和遍历的顺序相同。后序遍历就是遍历的顺序是访问顺序的逆过程。
* 而中序遍历却不同，它是在走完左边的时候，正准备走右边时才访问节点。这也就说明为什么中序和前序和后序在非递归上不太一样。
* 因此，中序的思路在于：
*     1. 首先栈的作用发生变化，入栈的顺序就是遍历的顺序，即遍历一个，入栈一个。
*     2. 设立一个指针，用于记录当前遍历的情况，可以叫“遍历指针”（当孩子为 NULL 是，“遍历指针”也会走到孩子那去）
*     3. 只有当“遍历指针”回头，即第二次访问到节点时，出栈（此时“遍历指针”指向的节点肯定和栈顶元素一样，是同一个节点）
*/
vector<int> traverse(BitNode head)
{
    stack<BitNode> nodeStack;
    vector<int> order;
    BitNode* currentNode = &head;
    // 当栈为空时，如果当前指针也为空（此时肯定是指向最后一个节点的右孩子（空））时，整个过程才代表结束。
    while (!nodeStack.empty() || currentNode != NULL)
    {
        // 不为空就入栈、一路向左
        if (currentNode != nullptr)
        {
            nodeStack.push(*currentNode);
            currentNode = currentNode->left;
        }
        // 如果为空，那就出栈，访问，回退，向右走
        else
        {
            // 出栈
            BitNode node = nodeStack.top();
            nodeStack.pop();
            // 访问
            order.push_back(node.value);
            // 回退
            // currentNode = &node;
            // 向右走
            currentNode = node.right;
        }
    }
    return order;
}

int main()
{
    //      4
    //   5     3
    //     1 7
    BitNode head(4);
    BitNode leftNode(5);
    BitNode rightNode(3);
    BitNode leaf_1(1);
    BitNode leaf_2(7);
    head.left = &leftNode;
    head.right = &rightNode;
    leftNode.right = &leaf_1;
    rightNode.left = &leaf_2;
    vector<int> order = preorderedTraverse(head);
    for (int i = 0; i < order.size(); i++)
    {
        cout << order[i] << "  ";
    }
    cout << endl;
    order = afterOrderedTraverse(head);
    for (int i = 0; i < order.size(); i++)
    {
        cout << order[i] << "  ";
    }
    cout << endl;
    order = traverse(head);
    for (int i = 0; i < order.size(); i++)
    {
        cout << order[i] << "  ";
    }
    cout << endl;
}

