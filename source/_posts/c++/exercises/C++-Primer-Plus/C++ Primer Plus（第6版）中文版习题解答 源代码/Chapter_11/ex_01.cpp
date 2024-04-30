
/*第十一章：编程练习 1 */
// randwalk.cpp -- using the Vector class
// compile with the vect.cpp file
#include <iostream>
#include <cstdlib>      // rand(), srand() prototypes
#include <ctime>        // time() prototype
#include <fstream>

#include "vect.h"

int main()
{
    using namespace std;
    using VECTOR::Vector;

    //创建输出文件对象fout
    ofstream fout;
    //创建磁盘文件randwalk.txt，保存输出的数据
    fout.open("randwalk.txt");

    srand(time(0));     // seed random-number generator
    double direction;
    Vector step;
    Vector result(0.0, 0.0);
    unsigned long steps = 0;
    double target;
    double dstep;
    cout << "Enter target distance (q to quit): ";
    while (cin >> target)
    {
        cout << "Enter step length: ";
        if (!(cin >> dstep))
            break;

        //使用fout对象和重定向操作符将字符串输出到文件，使用方法和cout类似
        fout << "Target Distance: " << target << ", Step Size: " << dstep << endl;

        while (result.magval() < target)
        {
            //本处需要记录漫步者的每一次步进号、和result数值
            //使用fout对象和重定向操作符将行走的编号和坐标输出到文件
            fout << steps<<" : " << result << endl;
            //vect类重载了<<操作符，因此可以直接使用fout输出到文件

            direction = rand() % 360;
            step.reset(dstep, direction, Vector::POL);
            result = result + step;
            steps++;
        }
        cout << "After " << steps << " steps, the subject "
                                     "has the following location:\n";
        cout << result << endl;

        //使用fout对象和重定向操作符将字符串输出到文件
        fout << "After " << steps << " steps, the subject "
                                     "has the following location:\n";
        fout << result << endl;

        result.polar_mode();
        cout << " or\n" << result << endl;
        cout << "Average outward distance per step = "
             << result.magval()/steps << endl;

        //使用fout对象和重定向操作符将字符串输出到文件
        fout << " or\n" << result << endl;
        fout << "Average outward distance per step = "
             << result.magval()/steps << endl;

        steps = 0;
        result.reset(0.0, 0.0);
        cout << "Enter target distance (q to quit): ";
    }
    cout << "Bye!\n";
    cin.clear();
    while(cin.get() != '\n')
        continue;
    return 0;
}
