/*第十六章：编程练习 3 */
// hangman.cpp -- some string methods
#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <cctype>
#include <fstream>
#include <vector>
/* 添加相应的头文件fstream 和 vector */
const int NUM = 26;

int main()
{
    using std::cout;
    using std::cin;
    using std::tolower;
    using std::endl;
    using std::string;
/* 原代码使用using声明，可以修改为using编译指令 */
/* 添加文件读取功能，创建文件对象，从文件内读取
 * 相应的单词 ，存入 string 的 vector 的对象内 */
    std::ifstream fin;
    fin.open("wordlist.txt", std::ifstream::in);
    if(!fin.is_open())
    {
        cerr<<"Can't open file wordlist.txt."<<endl;
        exit(EXIT_FAILURE);
    }
    string word;
    std::vector<string> wordlist;
    if(fin.good())
    {
        while(fin >> word)
            wordlist.push_back(word);
    }
    int length = wordlist.size();
    fin.close();
/* 数据读取完成 */
    std::srand(std::time(0));
    char play;
    cout << "Will you play a word game? <y/n> ";
    cin >> play;
    play = tolower(play);
    while (play == 'y')
    {
        string target = wordlist[std::rand() % NUM];
        int length = target.length();
        string attempt(length, '-');
        string badchars;
        int guesses = 6;
        cout << "Guess my secret word. It has " << length
             << " letters, and you guess\n"
             << "one letter at a time. You get " << guesses
             << " wrong guesses.\n";
        cout << "Your word: " << attempt << endl;
        while (guesses > 0 && attempt != target)
        {
            char letter;
            cout << "Guess a letter: ";
            cin >> letter;
            if (badchars.find(letter) != string::npos
                || attempt.find(letter) != string::npos)
            {
                cout << "You already guessed that. Try again.\n";
                continue;
            }
            int loc = target.find(letter);
            if (loc == string::npos)
            {
                cout << "Oh, bad guess!\n";
                --guesses;
                badchars += letter; // add to string
            }
            else
            {
                cout << "Good guess!\n";
                attempt[loc]=letter;
                // check if letter appears again
                loc = target.find(letter, loc + 1);
                while (loc != string::npos)
                {
                    attempt[loc]=letter;
                    loc = target.find(letter, loc + 1);
                }
            }
            cout << "Your word: " << attempt << endl;
            if (attempt != target)
            {
                if (badchars.length() > 0)
                    cout << "Bad choices: " << badchars << endl;
                cout << guesses << " bad guesses left\n";
            }
        }
        if (guesses > 0)
            cout << "That's right!\n";
        else
            cout << "Sorry, the word is " << target << ".\n";

        cout << "Will you play another? <y/n> ";
        cin >> play;
        play = tolower(play);
    }

    cout << "Bye\n";
    return 0;
}

