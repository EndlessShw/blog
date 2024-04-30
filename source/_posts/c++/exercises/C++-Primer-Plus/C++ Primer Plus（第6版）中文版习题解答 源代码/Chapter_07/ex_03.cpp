/*第七章：编程练习 3 */
#include <iostream>
using namespace std;

struct box{
    char maker[40];
    float height;
    float width;
    float length;
    float volume;
};
/* 结构体定义 */
void display(box);
void calc_volume(box *);
/* 函数的原型声明 */
int main() 
{
    box Orange = {"China",12,12,12,0};
    calc_volume(&Orange);
    display(Orange);
    /* 创建结构体变量并初始化，简单应用函数计算体积并显示 。*/
    return 0;
}
void display(box b)
{
    cout<<"This box made by "<<b.maker<<".\nAnd height = "<<b.height;
    cout<<", width = "<<b.width<<", length = "<<b.length<<", volume = ";
    cout<<b.volume<<".";
/* 输入box结构的基本数据信息 */
}
void calc_volume(box *pb)
{
    pb->volume = pb->width * pb->height * pb->length;
    cout<<"Calculate box's volume done."<<endl;
    /* 计算Volume ，并将其直接存在参数 pb指向的数据对象内 
     * 因此可以不使用返回值返回计算结果 */
}
