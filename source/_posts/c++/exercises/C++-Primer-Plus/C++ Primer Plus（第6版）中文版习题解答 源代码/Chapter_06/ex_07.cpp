/*第六章：编程练习 7
 * */
#include <iostream>
#include <cctype>

using namespace std;

int main()
{
    char words[40];
    int vowel, consonant, others;
    vowel = consonant = others = 0;
    cout<<"Enter words (q to quit):"<<endl;
    cin>>words;
    /* 设置变量，使用字符数组来实现单词数据输入*/
    while(strcmp(words,"q") != 0)
    {
        if(!isalpha(words[0]))
        {
            others ++;
        }
        /* 非字母开头的单词计数 */
        else{
            switch(words[0])
            {
                case 'a':
                case 'e':
                case 'i':
                case 'o':
                case 'u':
                    vowel++;
                    /* 元音字母单词计数*/
                    break;
                default:
                    consonant++;
                    /* 非元音字母单词计数*/
            }
        }
        cin>>words;
    }
    cout<<vowel<<" words beginning with vowels"<<endl;
    cout<<consonant<<" words beginning with consonants"<<endl;
    cout<<others<<" others"<<endl;
    return 0;
}

