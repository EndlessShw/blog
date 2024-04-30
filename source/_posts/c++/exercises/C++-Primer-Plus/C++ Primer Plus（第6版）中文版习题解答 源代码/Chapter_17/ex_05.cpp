/*第十七章：编程练习 5 */
#include <iostream>
#include <fstream>
#include <set>
#include <string>

using namespace std;

int main()
{
    ifstream fin_mat("mat.txt", ios_base::in);
    ifstream fin_pat("pat.txt", ios_base::in);
    /* 定义输入文件 */
    string guest;
    set<string> mat_guest, pat_guest, guest_set;
    /* 定义set<string> 对象，存储mat pat和总名单 */

    if(!fin_mat.is_open() || !fin_pat.is_open())
    {
        cout<<"Error open files."<<endl;
        exit(EXIT_FAILURE);
    }
    while(getline(fin_mat, guest) && guest.size() > 0)
        mat_guest.insert(guest);
    cout << "\nMat's friends are: \n";
    for(auto pd = mat_guest.begin(); pd != mat_guest.end(); pd++)
        cout << *pd << " ";
    /* 从输入文件读取mat名单，并存储set内 */
    while(getline(fin_pat, guest) && guest.size() > 0)
        pat_guest.insert(guest);
    cout << "\nPat's friends are: \n";
    for(auto pd = pat_guest.begin(); pd != pat_guest.end(); pd++)
        cout << *pd << " ";
    /* 从输入文件读取pat名单，并存储set内 */

    fin_pat.close();
    fin_mat.close();
    /* 关闭文件流 */
    guest_set.insert(mat_guest.begin(),mat_guest.end());
    guest_set.insert(pat_guest.begin(),pat_guest.end());
    /* 名单合并 */
    ofstream fout("guest.txt", ios_base::out);
    if(!fout.is_open())
    {
        cout<<"Error open files."<<endl;
        exit(EXIT_FAILURE);
    }

    for(auto pd = guest_set.begin(); pd != guest_set.end(); pd++)
        fout << *pd << " ";
    fout.close();
    /* 文件输出 */

    ifstream fin("guest.txt", ios_base::in);
    if(!fin.is_open())
    {
        cout<<"Error open files."<<endl;
        exit(EXIT_FAILURE);
    }
    /* 测试合并客人名单，并打印 */
    cout << "\nAll Guest list : \n";
    while(getline(fin, guest))
        cout << guest << " ";
    cout << endl;
    fin.close();
    return 0;
}

