
/*第七章：编程练习 10 */
#include <iostream>
using namespace std;
double add(double, double);
double subtract(double ,double);
double calculate(double, double, double (*)(double ,double));

int main(int argc, char *argv[]) 
{
    double q = calculate(2.5, 10.4, add);
    cout<<"The Answer of add is "<<q<<endl;
    double t = calculate(2.5, 10.4, subtract);
    cout<<"The Answer of substract is "<<t<<endl;
    return 0;
}

double add(double x, double y)
{
    return x + y;
}
double subtract(double x,double y){
    return x - y;
}

double calculate(double x, double y, double (*pf)(double x1, double x2)){
    return pf(x,y);
}



