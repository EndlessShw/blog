// 规格化并翻转字符串内的单词
#include <iostream>
#include <string>
using namespace std;

/**
 * 前后去掉空格，然后还要去除单词中的多余空格
 * 
 * \param str
 */
void formatStr(string& str)
{
    // 由于是缩短字符串，所以直接对其进行修改
    int slowPointer = 0;
    // 统计开头的空格
    int spaceBef = 0;
    for (int i = 0; i < str.size(); i++)
    {
        if (str[i] == ' ')
        {
            spaceBef++;
        }
        else
        {
            break;
        }
    }
    // 去掉末尾的空格
    int spaceAft = 0;
    for (int i = str.size() - 1; i >= 0; i--)
    {
        if (str[i] == ' ')
        {
            spaceAft++;
        }
        else
        {
            break;
        }
    }
    str.resize(str.size() - spaceAft);
    // 对字符串进行整形
    int resultLength = 0;
    for (int i = spaceBef; i < str.size(); i++)
    {
        // 判断他前一位是不是空格
        if (str[i] != ' ' || (str[i] == ' ' && str[i - 1] != ' '))
        {
            str[slowPointer] = str[i];
            slowPointer++;
            resultLength++;
        }
    }
    str.resize(resultLength);
}

string reverseWords(string s)
{
    // 首先将字符串进行规则化
    formatStr(s);
    // 然后对其进行翻转
    int begin = 0;
    int end = s.size() - 1;
    while (begin <= end)
    {
        char temp = s[begin];
        s[begin] = s[end];
        s[end] = temp;
        begin++;
        end--;
    }
    cout << s << endl;
    // 双指针再单词内翻转
    begin = 0;
    for (int i = 0; i < s.size(); i++)
    {
        if (s[i + 1] == ' ' || i == s.size() - 1)
        {
            end = i;
            while (begin <= end)
            {
                char temp = s[begin];
                s[begin] = s[end];
                s[end] = temp;
                begin++;
                end--;
            }
            begin = i + 2;
        }
    }
    return s;
}

int main()
{
    string s = "the sky is blue";
    //formatStr(s);
    cout << reverseWords(s) << endl;

}
