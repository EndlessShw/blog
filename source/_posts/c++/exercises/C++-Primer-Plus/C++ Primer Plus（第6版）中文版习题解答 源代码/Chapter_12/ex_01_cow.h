/*第十二章：编程练习 1 */
//cow.h
#ifndef COW_H_
#define COW_H_

class Cow {
    char name[20];
    char * hobby;
    double weight;
public:
    Cow();
    Cow(const char * nm, const char * ho, double wt);
    Cow(const Cow & c);
    ~Cow();
    Cow & operator=(const Cow & c);
    void ShowCow() const;             //display all cow data
};
#endif

