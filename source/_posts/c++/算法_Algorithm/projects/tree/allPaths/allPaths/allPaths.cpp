// 求所有叶子节点的路径
#include <iostream>
#include <vector>
#include <string>
using namespace std;

struct BitNode
{
    int value;
    BitNode* left;
    BitNode* right;
    BitNode(int value) : value(value), left(nullptr), right(nullptr) {}
};

/**
 * 这题涉及到回溯，可以去看代码随想录中针对“回溯”的写法，去学习回溯.
 */
vector<string> paths;
void getPath(BitNode* node, string path)
{
    // 中
    path = path + to_string(node->value) + "->";
    // 左
    if (node->left)
    {
        getPath(node->left, path);
    }
    // 右
    if (node->right)
    {
        getPath(node->right, path);
    }
    if (node->left == nullptr && node->right == nullptr)
    {
        paths.push_back(path.substr(0, path.size() - 2));
    }
}


int main()
{
    BitNode* head = new BitNode(1);
    head->left = new BitNode(2);
    head->right = new BitNode(3);
    head->left->left = new BitNode(5);
    getPath(head, "");
    for (int i = 0; i < paths.size(); i++)
    {
        cout << paths[i] << endl;
    }
}

