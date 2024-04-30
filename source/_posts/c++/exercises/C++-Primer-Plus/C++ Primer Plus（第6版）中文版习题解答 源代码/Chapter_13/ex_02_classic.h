/*第十三章：编程练习 2 */
#ifndef CLASSIC_H
#define CLASSIC_H
//base class
class Cd{ // represents a CD disk
private:
    char* performers;
    char* label;
    int selections; // number of selections
    double playtime; // playing time in minutes
/*修改数据成员为指针，实现动态存储 */
public:
    Cd(const char * sl, const char * s2, int n, double x);
    Cd(const Cd & d);
    Cd();
    virtual ~Cd();
    virtual void Report() const; // reports all CD data
    virtual Cd & operator=(const Cd & d);
};

class Classic : public Cd{
private:
    char* works;
/*修改数据成员为指针，实现动态存储 */
public:
    Classic();
    Classic(const Classic& c);
    Classic(const char* s1,const char* s2, const char* s3,int n,double x);
    ~Classic();
    virtual void Report()const ;
    Classic& operator=(const Classic& c);
};

#endif //classic.h

