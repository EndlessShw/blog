/*第十七章：编程练习 3 */
#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        cout<<"Usage: "<<argv[0]<<" srcfile desfile"<<endl;
        exit(EXIT_FAILURE);
    }
    /*检查命令行参数 */
    char ch;

    ifstream fin(argv[1],ios_base::in);
    ofstream fout(argv[2],ios_base::out);
    if(!fin.is_open())
    {
        cout << "Can't open the file " << argv[1] << " !"<<endl;
        exit(EXIT_FAILURE);
    }
    if(!fout.is_open())
    {
        cout << "Can't open the file " << argv[2] << " !"<<endl;
        exit(EXIT_FAILURE);
    }
    /* 检查文件打开状态 */
    while(fin.get(ch)) fout << ch;
    /*文件循环读取、复制 */
    fin.close();
    fout.close();
    return 0;
}


