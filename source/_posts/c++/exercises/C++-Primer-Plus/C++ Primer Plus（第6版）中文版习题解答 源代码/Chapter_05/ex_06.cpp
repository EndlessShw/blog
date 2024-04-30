/*第五章：编程练习 6 */
#include <iostream>
using namespace std;
int main()
{
    const string Month[] = {"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
    int sale_amount[3][12]={};
    /* 定义二维数组，表示三年内每个月的销售数据，可以通过行列表格来理解
     * 销售数组通过{}初始化所有数据为 0 */
    unsigned int sum = 0;
    for(int i = 0; i < 3; i++)
    {
        cout<<"Starting "<<i<<" year's data."<<endl;
        for(int j = 0;j < 12 ;j++)
        {
            cout<<"Enter the sale amount of "<<Month[j]<<" :";
            cin>>sale_amount[i][j];
        }
        cout<<"End of "<<i+1<<" year's data."<<endl;
    }
    /*通过循环的嵌套实现二维数组的数据输入，内部循环是每年12个月，外部循环是3年 */
    cout<<"Input DONE!"<<endl;

    for(int i = 0; i < 3; i++)
    {
        for(int j = 0;j < 12 ;j++)
        {
            cout<<Month[i]<<" SALE :"<<sale_amount[i][j]<<endl;
            sum += sale_amount[i][j];
        }
        cout<<"Total sale "<<sum<<" cars in "<<i+1<<" year."<<endl;
    }
    /*通过循环的嵌套实现二维数组的每年数据计算，内部循环是每年12个月，所以每年的销售额
     * 显示应当在外部循环打印。 */
    return 0;
}
