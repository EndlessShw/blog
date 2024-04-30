/*第十七章：编程练习 1 */
#include <iostream>

int main()
{
    char input;
    int count = 0;
    std::cout << "Enter a phase: ";
    while(std::cin.peek() != '$')
    /*peek()函数检查，并未清空缓冲区 */
    {
        std::cin.get(input);
        count++;
    }
    std::cout << count << " chars.\n";
    return 0;
}

