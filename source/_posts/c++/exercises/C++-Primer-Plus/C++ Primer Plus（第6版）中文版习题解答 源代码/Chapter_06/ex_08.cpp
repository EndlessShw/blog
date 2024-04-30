/*第六章：编程练习 8
 * */
#include <iostream>
#include <fstream>
using namespace std;

int main() 
{
    ifstream fin;
    string file_name;
    cout<<"Enter the file name: ";
    getline(cin, file_name);
    /* 等待用户输入文件名 */
    fin.open(file_name);
    /* 通过文件流对象打开文件 */
    if(!fin.is_open()){
        cout<<"Error to open file."<<endl;
        exit(EXIT_FAILURE);
    }
    /* 如果打开文件错误，则终止程序 */
    char read_char;
    int char_counter = 0;
    while(!fin.eof()){
        fin>>read_char;
        char_counter++;
    }
    /* 通过eof()函数判断是否到达文件末尾 */
    cout<<"The file "<<file_name<<" contains "<<char_counter<<" characters."<<endl;
    fin.close();
    /* 关闭文件 */
    return 0;
}
