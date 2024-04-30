// 删除倒数的节点
#include <iostream>
using namespace std;

struct ListNode
{
    int val;
    ListNode* next;
    ListNode() : val(0), next(nullptr) {};
    ListNode(int val) : val(val), next(nullptr) {};
    ListNode(ListNode* next) : val(0), next(next) {};
    ListNode(int val, ListNode* next) : val(val), next(next) {};
};

ListNode* removeNthFromEnd(ListNode* head, int n) {
    // 设立一个头节点，从而方便操作
    ListNode* fakeHead = new ListNode(head);
    head = fakeHead;
    ListNode* after = fakeHead;
    for (int i = 0; i < n; i++)
    {
        after = after->next;
    }
    while (after->next)
    {
        after = after->next;
        head = head->next;
    }
    // 此时 head 为待删除节点的前一个节点
    after = head->next;
    // 删 after 所指向的节点
    head->next = after->next;
    after->next = nullptr;
    delete after;
    // head 也要删除
    head = nullptr;
    delete head;
    // 这里一定是返回虚拟头节点的下一个，因为当节点只有一个时，head 会被删除
    return fakeHead->next;
}

int main()
{
    ListNode* head = new ListNode(1);
    head = removeNthFromEnd(head, 1);
    cout << head->val << endl;
}
