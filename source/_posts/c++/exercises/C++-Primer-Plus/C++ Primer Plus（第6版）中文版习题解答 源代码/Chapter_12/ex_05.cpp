/*第十二章：编程练习 5 */
/*使用程序清单12.10和12.11的queue.h头文件和queue.cpp定义文件 */
// bank.cpp -- using the Queue interface
// compile with queue.cpp
#include <iostream>
#include <cstdlib> // for rand() and srand()
#include <ctime>   // for time()
#include "queue.h"
const int MIN_PER_HR = 60;
const int MIN_SIM_HOURS = 150;

bool newcustomer(double x); // is there a new customer?

int main()
{
    using std::cin;
    using std::cout;
    using std::endl;
    using std::ios_base;
// setting things up
    std::srand(std::time(0));    //  random initializing of rand()

    cout << "Case Study: Bank of Heather Automatic Teller\n";
    cout << "Enter maximum size of queue: ";
    int qs;
    cin >> qs;
    Queue line(qs);         // line queue holds up to qs people

    cout << "The number of simulation hours >= 100. "<<endl;

    /* 固定最短时间为MIN_SIM_HOURS，当前常量MIN_SIM_HOURS为150。 */
    int hours = MIN_SIM_HOURS;              //  hours of simulation
    // simulation will run 1 cycle per minute
    long cyclelimit = MIN_PER_HR * hours; // # of cycles

    //cout << "Enter the average number of customers per hour: ";
    double perhour = 0;         //  average # of arrival per hour
    Item temp;              //  new customer data
    double average_wait = 0;
/* 为了检测该临界值，通过循环从perhour = 1 开始，进行模拟和计算，当排队时间
 * 大于等于1时停止循环，此时打印的最后一组数据就是当前ATM机的排队状态。*/
// running the simulation
    while(average_wait < 1)
    {
        double min_per_cust;    //  average time between arrivals
        long turnaways = 0;     //  turned away by full queue
        long customers = 0;     //  joined the queue
        long served = 0;        //  served during the simulation
        long sum_line = 0;      //  cumulative line length
        int wait_time = 0;      //  time until autoteller is free
        long line_wait = 0;     //  cumulative time in line
        perhour++;
        if(!line.isempty()) line.dequeue(temp);
         /* 每次进入循环，首先清空ATM排队队列 */
        for (int cycle = 0; cycle < cyclelimit; cycle++)
        {
            min_per_cust = MIN_PER_HR / perhour;
            if (newcustomer(min_per_cust))  // have newcomer
            {
                if (line.isfull())
                    turnaways++;
                else
                {
                    customers++;
                    temp.set(cycle);    // cycle = time of arrival
                    line.enqueue(temp); // add newcomer to line
                }
            }
            if (wait_time <= 0 && !line.isempty())
            {
                line.dequeue (temp);      // attend next customer
                wait_time = temp.ptime(); // for wait_time minutes
                line_wait += cycle - temp.when();
                served++;
            }
            if (wait_time > 0)
                wait_time--;
            sum_line += line.queuecount();
        }
        average_wait = (double) line_wait / served;
        if(average_wait < 1){
            if (customers > 0)
            {
                cout << "customers accepted: " << customers << endl;
                cout << "  customers served: " << served << endl;
                cout << "         turnaways: " << turnaways << endl;
                cout << "average queue size: ";
                cout.precision(2);
                cout.setf(ios_base::fixed, ios_base::floatfield);
                cout << (double) sum_line / cyclelimit << endl;
                cout << " average wait time: "
                     << (double) line_wait / served << " minutes\n";
            }
            else
                cout << "No customers!\n";
            cout<<"The average "<<perhour<<" of arrival per hour, and average wait time is "
                <<average_wait<<endl;
        }
    }
// reporting results
    cout << "Done!\n";
    return 0;
}

//  x = average time, in minutes, between customers
//  return value is true if customer shows up this minute
bool newcustomer(double x)
{
    return (std::rand() * x / RAND_MAX < 1);
}

