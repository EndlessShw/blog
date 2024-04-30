/*第十七章：编程练习 4 */
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

int main()
{
    string line;

    ifstream fin1("file1.txt",ios_base::in);
    ifstream fin2("file2.txt",ios_base::in);
    ofstream fout("CombFile.txt",ios_base::out);
    /*打开三个文件，准备读写处理 */
    if(fin1.is_open() && fin2.is_open() && fout.is_open())
    {
    /*判断文件打开是否正常 */
        while(!fin1.eof() || !fin2.eof())
        {
            if(getline(fin1, line) && line.size() > 0)
                fout << line;
            if(getline(fin2, line) && line.size() > 0)
                fout << line;
             /*while循环的循环条件为两个输入文件均到末尾，否则循环读写 */
            fout << endl;
            /*文件一行写入完成，输出换行符 */
        }
    }
    else
    {
        cout << "Can't open the file!\n";
        exit(EXIT_FAILURE);
    }
    fin1.close();
    fin2.close();
    fout.close();
    return 0;
}
