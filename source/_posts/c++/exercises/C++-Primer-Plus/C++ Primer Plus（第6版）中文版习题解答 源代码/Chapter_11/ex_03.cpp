/*第十一章：编程练习 3 */
// randwalk.cpp -- using the Vector class
// compile with the vect.cpp file
#include <iostream>
#include <cstdlib>      // rand(), srand() prototypes
#include <ctime>        // time() prototype
#include "vect.h"
int main()
{
    using namespace std;
    using VECTOR::Vector;
    srand(time(0));     // seed random-number generator
    double direction;
    Vector step;
    Vector result(0.0, 0.0);
    unsigned long steps = 0;
    double target;
    double dstep;
    /*
    定义变量记录最高、最低和平均步数
    */
    unsigned long Max = 0;
    unsigned long Min = 0;
    unsigned long Sum = 0;
    unsigned int count = 0;

    cout << "Enter target distance (q to quit): ";
    while (cin >> target)
    {
        cout << "Enter step length: ";
        if (!(cin >> dstep))
            break;

        while (result.magval() < target)
        {
            direction = rand() % 360;
            step.reset(dstep, direction, Vector::POL);
            result = result + step;
            steps++;
        }
        cout << "After " << steps << " steps, the subject "
                                     "has the following location:\n";

        cout << result << endl;
        result.polar_mode();
        cout << " or\n" << result << endl;
        cout << "Average outward distance per step = "
             << result.magval()/steps << endl;
        /*每次计算完成后，统计最大值、最小值和平均步数。steps置0
         *
         * */
        if (Max < steps) Max = steps;
        if (Min == 0) Min = Max;
        if (Min > steps) Min = steps;
        Sum += steps;
        count++;
        steps = 0;
        result.reset(0.0, 0.0);
        cout << "Enter target distance (q to quit): ";
    }
    cout << "Your input "<<count<<" times, and statistics info :"<<endl;
    cout << "Max Step = " << Max << endl;
    cout << "Mix Step = " << Min << endl;
    cout << "Average Step =  " << Sum/count << endl;

    cout << "Bye!\n";
    cin.clear();
    while(cin.get() != '\n')
        continue;
    return 0;
}

