/*第十三章：编程练习 1 */
#ifndef CLASSIC_H
#define CLASSIC_H
//base class
class Cd{ // represents a CD disk
private:
    char performers [50];
    char label [20];
    int selections; // number of selections
    double playtime; // playing time in minutes
public:
    Cd(const char * sl, const char * s2, int n, double x);
    Cd(const Cd & d);
    Cd();
    virtual ~Cd(){};
    virtual void Report() const; // reports all CD data
    Cd & operator=(const Cd & d);
};
class Classic : public Cd{
private:
    char works[50];
public:
    Classic();
    Classic(const Classic& c);
    Classic(const char* s1,const char* s2, const char* s3,int n,double x);
    ~Classic(){};
    virtual void Report()const ;
    Classic& operator=(const Classic& c);
};

#endif //classic.h

