
/*第六章：编程练习 3
 * */
#include <iostream>
using namespace std;

void showmenu();
/* 菜单显示函数的声明 */
int main()
{
    char choice;
    showmenu();
    cin.get(choice);
    /* 显示菜单，并读取用户输入，保存至choice变量 */
    while(choice != 'c' && choice != 'p'&& choice != 't'&& choice != 'g' )
    {
        cin.get();
        cout<<"Please enter a c, p, t, or g: ";
        cin.get(choice);
    }
    /* 判断用户输入是否符合菜单选项，如果不，则要求下一次输入 */
    switch(choice)
    {
        case 'c':
            break;
        case 'p':
            break;
        case 't':
            cout<<"A maple is a tree.";
            break;
        case 'g':
            break;

    }
    /* 针对输入的菜单作出多重新选择和反馈 */
    return 0;
}

void showmenu()
{
    cout<<"Please enter one of the following choices:\n";
    cout<<"c) carnivore\t\t\tp) pianist\n";
    cout<<"t) tree\t\t\t\tg) game\n";
}
/* 菜单显示函数，只负责菜单信息的打印 */

