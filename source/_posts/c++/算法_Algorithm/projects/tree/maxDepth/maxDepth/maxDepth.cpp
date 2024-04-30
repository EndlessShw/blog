// 求一颗二叉树的深度
#include <iostream>
#include <queue>
#include <vector>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {};
};

// 层次遍历
int levelTraverse(BitNode* head)
{
    vector<vector<int>> results;
    queue<BitNode*> levelQueue;
    levelQueue.push(head);
    while (!levelQueue.empty())
    {
        vector<int> result;
        int round = levelQueue.size();
        for (int i = 0; i < round; i++)
        {
            BitNode* temp = levelQueue.front();
            levelQueue.pop();
            result.push_back(temp->value);
            if (temp->left)
            {
                levelQueue.push(temp->left);
            }
            if (temp->right)
            {
                levelQueue.push(temp->right);
            }
        }
        results.push_back(result);
    }
    return results.size();
}

/*
* 思路二：后序遍历
* 前序遍历从上往下，后序遍历从下网上，将数据返回给根节点。
* 因此求一棵树的深度用前序遍历，求一棵树的高度用后序遍历。
* 因为求最大深度，实际上就是求根节点的高度，因此可以采用后序遍历（递归），
* 一层一层向上传 max(左高 + 右高） + 1
*/

int main()
{   
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

    int depth = levelTraverse(tree);
    cout << "深度为：" << depth << endl;
}

