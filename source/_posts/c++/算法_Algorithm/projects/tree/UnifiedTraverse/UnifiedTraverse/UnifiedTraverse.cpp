// 统一化的二叉树遍历
#include <iostream>
#include <stack>
#include <vector>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {}
};

// 中序遍历
vector<int> traverse(BitNode head)
{
    // 入栈的顺序和遍历的顺序相同
    // 注意这里的栈改存节点指针，因为这样才能存 NULL，普通的结构体变量没有 NULL
    // NULL 作为标记，表示弹出这个时，下一个栈的节点就是要访问的节点
    stack<BitNode*> traceStack;
    vector<int> result;
    traceStack.push(&head);
    // 用一个变量来记录出栈的元素
    BitNode* node = nullptr;
    while (!traceStack.empty())
    {
        node = traceStack.top();
        traceStack.pop();
        // 如果弹出的节点不是标记，表示要遍历
        if (node != nullptr)
        {
            // 遍历的顺序是左中右，那么入栈顺序就是右中左
            // 此时中间的元素是要访问的元素，因此在遍历到中间的元素时，塞个标记位子
            if (node->right != nullptr)
            {
                traceStack.push(node->right);
            }
            traceStack.push(node);
            // 塞入标记
            traceStack.push(nullptr);
            if (node->left != nullptr)
            {
                traceStack.push(node->left);
            }
        }
        // 如果弹出的是标记，那就再弹出一个（此时这个肯定是中间节点），然后访问
        if (node == nullptr)
        {
            node = traceStack.top();
            traceStack.pop();
            // 访问
            result.push_back(node->value);
        }
    }
    return result;
}

// 前序遍历
vector<int> preOrderedTraverse(BitNode head)
{
    // 出栈的顺序和遍历的顺序相同
    // 注意这里的栈改存节点指针，因为这样才能存 NULL，普通的结构体变量没有 NULL
    // NULL 作为标记，表示弹出这个时，下一个栈的节点就是要访问的节点
    stack<BitNode*> traceStack;
    vector<int> result;
    traceStack.push(&head);
    // 用一个变量来记录出栈的元素
    BitNode* node = nullptr;
    while (!traceStack.empty())
    {
        node = traceStack.top();
        traceStack.pop();
        // 如果弹出的节点不是标记，表示要遍历
        if (node != nullptr)
        {
            if (node->right != nullptr)
            {
                traceStack.push(node->right);
            }
            if (node->left != nullptr)
            {
                traceStack.push(node->left);
            }
            // 先遍历中间，然后塞入中间节点
            traceStack.push(node);
            // 塞入标记
            traceStack.push(nullptr);
        }
        // 如果弹出的是标记，那就再弹出一个（此时这个肯定是中间节点），然后访问
        if (node == nullptr)
        {
            node = traceStack.top();
            traceStack.pop();
            // 访问
            result.push_back(node->value);
        }
    }
    return result;
}

// 后序遍历
vector<int> afterOrderedTraverse(BitNode head)
{
    // 出栈的顺序和遍历的顺序相同
    // 注意这里的栈改存节点指针，因为这样才能存 NULL，普通的结构体变量没有 NULL
    // NULL 作为标记，表示弹出这个时，下一个栈的节点就是要访问的节点
    stack<BitNode*> traceStack;
    vector<int> result;
    traceStack.push(&head);
    // 用一个变量来记录出栈的元素
    BitNode* node = nullptr;
    while (!traceStack.empty())
    {
        node = traceStack.top();
        traceStack.pop();
        // 如果弹出的节点不是标记，表示要遍历
        if (node != nullptr)
        {
            // 先遍历中间，然后塞入中间节点
            traceStack.push(node);
            // 塞入标记
            traceStack.push(nullptr);
            if (node->right != nullptr)
            {
                traceStack.push(node->right);
            }
            if (node->left != nullptr)
            {
                traceStack.push(node->left);
            }
        }
        // 如果弹出的是标记，那就再弹出一个（此时这个肯定是中间节点），然后访问
        if (node == nullptr)
        {
            node = traceStack.top();
            traceStack.pop();
            // 访问
            result.push_back(node->value);
        }
    }
    return result;
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
    vector<int> result = traverse(head);
    for (int i = 0; i < result.size(); i++)
    {
        cout << result[i] << "  ";
    }
    cout << endl;
    result = preOrderedTraverse(head);
    for (int i = 0; i < result.size(); i++)
    {
        cout << result[i] << "  ";
    }
    cout << endl;
    result = afterOrderedTraverse(head);
    for (int i = 0; i < result.size(); i++)
    {
        cout << result[i] << "  ";
    }
    cout << endl;

}

