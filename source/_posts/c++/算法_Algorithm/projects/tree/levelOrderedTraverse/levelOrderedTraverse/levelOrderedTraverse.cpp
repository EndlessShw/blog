// 层序遍历
#include <iostream>
#include <vector>
#include <queue>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {};
};

// 非递归层序遍历
vector<vector<int>> noRecursionLevelOrderedTraverse(const BitNode head)
{
    vector<vector<int>> results;
    queue<BitNode> level;
    level.push(head);
    while (!level.empty())
    {
        vector<int> result;
        int round = level.size();
        // 一轮循环
        for (int i = 0; i < round; i++)
        {
            // 出队
            BitNode node = level.front();
            level.pop();
            // 访问
            result.push_back(node.value);
            // 左右孩子入队
            if (node.left != nullptr)
            {
                level.push(*node.left);
            }
            if (node.right != nullptr)
            {
                level.push(*node.right);
            }
        }
        results.push_back(result);
    }
    return results;
}

/*
* 递归的层序遍历，因为是递归，所以不需要队列
*/
void levelOrderedTraverse(const BitNode* node, vector<vector<int>>& results, int depth)
{
    // 递归的退出条件
    if (node == nullptr)
    {
        return;
    }
    // 初始化
    if (results.size() <= depth) results.push_back(vector<int>());
    // 访问
    results[depth].push_back(node->value);
    // 左孩子
    levelOrderedTraverse(node->left, results, depth + 1);
    // 右孩子
    levelOrderedTraverse(node->right, results, depth + 1);
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
    vector<vector<int>> results = noRecursionLevelOrderedTraverse(head);
    for (int i = 0; i < results.size(); i++)
    {
        for (int j = 0; j < results[i].size(); j++)
        {
            cout << results[i][j] << "  ";
        }
        cout << endl;
    }
    vector<vector<int>> results2;
    levelOrderedTraverse(&head, results2, 0);
    for (int i = 0; i < results2.size(); i++)
    {
        for (int j = 0; j < results2[i].size(); j++)
        {
            cout << results2[i][j] << "  ";
        }
        cout << endl;
    }
}

