
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

using namespace std;
const int LIMIT = 50;

void ShowStr(const string & str);
void GetStrs(ifstream & fin, vector<string> & v);

class Store
{
private:
    string str;
    ofstream* fout;
public:
    Store(ofstream &out):fout(&out){ }
    bool operator()(const string & str);
    ~Store() {}
};
/* 定义Store 函数符 */

void ShowStr(const string & str)
{
    cout << str << endl;
}

void GetStrs(ifstream & fin, vector<string> & v)
{
    unsigned int len;
    char* p;
    while(fin.read((char *)&len, sizeof len))
    {
        p = new char[len];
        fin.read(p, len);
        v.push_back(p);
    }
}
/* 读取字符串，先读取字符串长度数据，再按照该长度读取指定长度的字符串 */

bool Store::operator()(const string & str)
{
    unsigned int len = str.length();
    if (fout->is_open())
    {
        fout->write((char *)&len, sizeof len);
        fout->write(str.data(), len);
        return true;
    }
    else return false;
}
/* 函数符将字符串写入文件，使用题目例子中的write()函数，
 * 先写入字符串长度，再写入字符串 */

int main()
{
    using namespace std;
    vector<string> vostr;
    string temp;
// acquire strings
    cout << "Enter strings (empty line to quit):\n";
    while (getline(cin, temp) && temp[0] != '\0')
        vostr.push_back(temp);
    cout << "Here is your input.\n";
    for_each(vostr.begin(), vostr.end(), ShowStr);

//store in a file
    ofstream fout("strings.txt", ios_base::out | ios_base::binary);
    for_each(vostr.begin(), vostr.end(), Store(fout));
    fout.close();

//recover filer contents
    vector<string> vistr;
    ifstream fin("strings.txt", ios_base::in | ios_base::binary);
    if (!fin.is_open())
    {
        cerr << "Could not open the file for input.\n";
        exit(EXIT_FAILURE);
    }

    GetStrs(fin, vistr);
    cout << "\nHere are the strings read from the file:\n";
    for_each(vistr.begin(), vistr.end(), ShowStr);

    return 0;
}




