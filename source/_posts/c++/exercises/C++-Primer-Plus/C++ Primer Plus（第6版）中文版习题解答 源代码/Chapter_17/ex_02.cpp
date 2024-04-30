/*第十七章：编程练习 2 */
#include <iostream>
#include <fstream>

using namespace std;
int main(int argc, char *argv[])
{
    if(argc == 1)
    {
        cout<<"Usage: "<<argv[0]<<" filename[s]"<<endl;
        exit(EXIT_FAILURE);
    }
    /*命令行参数的数量检查 */
    char ch;
    ofstream fout(argv[1],ios_base::out);
    if(fout.is_open())
    {
        cout << "Inpue the data:\n";
        while(cin.get(ch) && ch != EOF)
            fout << ch;
    /* 循环写入文件，直到输入EOF */
    }
    else
    {
        cout << "error to create the file!";
        exit(EXIT_FAILURE);
    }
    fout.close();
    return 0;
}

