/*第十二章：编程练习 6 */
/*使用程序清单12.10和12.11的queue.h头文件和queue.cpp定义文件 */
// bank.cpp -- using the Queue interface
// compile with queue.cpp
#include <iostream>
#include <cstdlib> // for rand() and srand()
#include <ctime>   // for time()
#include "queue.h"
const int MIN_PER_HR = 60;
const int MIN_SIM_HOURS = 1500;

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
    Queue line_one(qs);         // line queue holds up to qs people
    Queue line_two(qs);         // line queue holds up to qs people

    cout << "The number of simulation hours >= 100. "<<endl;
    /* 固定最短时间为一小时*/
    int hours = MIN_SIM_HOURS;              //  hours of simulation
    // simulation will run 1 cycle per minute
    long cyclelimit = MIN_PER_HR * hours; // # of cycles

    //cout << "Enter the average number of customers per hour: ";
    double perhour = 0;     //  average # of arrival per hour
    double min_per_cust;    //  average time between arrivals
    Item temp;              //  new customer data
    long turnaways;     //  turned away by full queue
    long customers, customers_one, customers_two;     //  joined the queue
    long served;        //  served during the simulation
    long sum_line_one, sum_line_two;      //  cumulative line length
    int wait_time_one, wait_time_two;      //  time until autoteller is free
    long line_wait;     //  cumulative time in line
    double average_wait = 0;
/* 分别定义两个ATM队列需要的变量，部分变量可共用 */

// running the simulation
    while(average_wait < 1.0 ){
        turnaways = 0;     //  turned away by full queue
        customers = customers_one = customers_two = 0;     //  joined the queue
        served = 0;        //  served during the simulation
        sum_line_one = sum_line_two = 0;      //  cumulative line length
        wait_time_one = wait_time_two = 0;      //  time until autoteller is free
        line_wait = 0;     //  cumulative time in line
        perhour++;
        min_per_cust = MIN_PER_HR / perhour;
        while(!line_one.isempty()) line_one.dequeue(temp);
        while(!line_two.isempty()) line_two.dequeue(temp);
        /* 每次进入循环，首先清空ATM排队队列 */
        for (int cycle = 0; cycle < cyclelimit; cycle++)
        {

            if (newcustomer(min_per_cust))  // have newcomer
            {
                if (line_one.isfull() && line_two.isfull())
                    turnaways++;
                else
                {
                    customers++;
                    temp.set(cycle);    // cycle = time of arrival
                    if(line_one.queuecount() < line_two.queuecount()) {
                        line_one.enqueue(temp); 
                        customers_one++;
                    }else {
                        line_two.enqueue(temp);
                        customers_two++;
                    }                          
                   /* 平均处理两个ATM排队人数*/
                }
            }
            if (wait_time_one <= 0 && !line_one.isempty())
            {
                line_one.dequeue (temp);      // attend next customer
                wait_time_one = temp.ptime(); // for wait_time minutes
                line_wait += cycle - temp.when();
                served++;
            }
            if (wait_time_two <= 0 && !line_two.isempty())
            {
                line_two.dequeue (temp);      // attend next customer
                wait_time_two = temp.ptime();    // for wait_time minutes
                line_wait += cycle - temp.when();
                served++;
            }
            if (wait_time_one > 0) wait_time_one--;
            if (wait_time_two > 0) wait_time_two--;
            sum_line_one += line_one.queuecount();
            sum_line_two += line_two.queuecount();
        }
        average_wait = (double) (line_wait)/ (served);
        if(average_wait < 1){
            if (customers > 0)
            {
                cout << "customers accepted: " << customers << endl;
                cout << "  customers served: " << served << endl;
                cout << "         turnaways: " << turnaways << endl;
                cout << "average queue size: ";
                cout.precision(2);
                cout.setf(ios_base::fixed, ios_base::floatfield);
                cout << (double) (sum_line_one + sum_line_two)/ cyclelimit << endl;
                cout << " average wait time: "
                     << average_wait << " minutes\n";
            }
            else
                cout << "No customers!\n";
            cout<<"The average "<<perhour<<" of arrival per hour, and average wait time is "
                <<average_wait<<endl;
        }
    }

    cout << "Done!\n";
    return 0;
}

//  x = average time, in minutes, between customers
//  return value is true if customer shows up this minute
bool newcustomer(double x)
{
    return (std::rand() * x / RAND_MAX < 1);
}



