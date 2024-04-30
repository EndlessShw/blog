// 翻转链表
#include <iostream>
using namespace std;

struct ListNode
{
    int val;
    ListNode* next;
    ListNode() : val(0), next(nullptr) {};
    ListNode(int val) : val(val), next(nullptr) {};
    ListNode(int val, ListNode* next) : val(val), next(next) {}
};
/**
 * 带头节点的链表翻转.
 * 
 * \param head
 * \return 
 */
ListNode* reverseList(ListNode* head) {
    if (!head)
    {
        return head;
    }
    // head 一直指向头位
    // 用双指针
    ListNode* before = head;
    ListNode* after = head->next;
    while (after)
    {
        // todo 节点交换也可以考虑只换节点内的数据
        // 每一轮前段的尾节点指向后一段首节点的第二个点
        before->next = after->next;
        // 后一段首节点指向前一段的首节点
        after->next = head;
        // head 要变成首部
        head = after;
        // after 后移一位
        after = before->next;
    }
    return head;
}

int main()
{
    // 注意 head 是指针，他初始化时就可以指向一个节点。head 的内容就是节点
    ListNode* head = new ListNode(1);
    head->next = new ListNode(2);
    head->next->next = new ListNode(3);
    head->next->next->next = new ListNode(4);
    head->next->next->next->next = new ListNode(5);
    head = reverseList(head);
    cout << head->next->val << " "
        << head->next->next->val << " "
        << head->next->next->next->val << " "
        << head->next->next->next->next->val << " "
        << endl;
}
