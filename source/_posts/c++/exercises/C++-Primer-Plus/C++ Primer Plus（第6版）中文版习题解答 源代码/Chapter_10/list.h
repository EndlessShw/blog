
/* list.h 列表的声明 */
typedef unsigned long Item;
/* 此处声明unsigned long 为 Item 元素的类型 */

void visit_Item(Item&);
/* 针对每一个类型需要定义对应的数据访问函数，此处是打印功能 */
class List
{
private:
    enum {MAX = 10};
    Item items[MAX];    // holds list items
    /* 本处使用数组形式维护列表 */
    int top;            // index for top list item
public:
    List();
    bool isempty() const;
    bool isfull() const;
    bool add(const Item & item);   // add item to list
    void visit(void (*pf)(Item &));
};
