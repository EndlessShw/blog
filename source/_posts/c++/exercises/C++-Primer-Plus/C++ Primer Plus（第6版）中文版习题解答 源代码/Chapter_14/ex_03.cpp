/*第十四章：编程练习 3 */
#include <iostream>
#include <string>
using namespace std;

int main()
{
    QueueTp<Worker> lolas;
    Worker w1;
    w1.Set();
    lolas.enqueue(w1);
    Worker w2;
    lolas.dequeue(w2);
    w2.Show();
    cout << "Bye.\n";
    return 0;
}
