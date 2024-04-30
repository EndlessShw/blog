/*第十四章：编程练习 5 */
/*使用题目给定的emp.h和useemp.cpp，下面仅为emp.cpp */

#include "emp.h"
using namespace std;
class highfink: public manager, public fink // management fink
{
public:
    highfink();
    highfink(const std::string & fn, const std::string & ln,
             const std::string & j, const std::string & rpo, int ico);
    highfink(const abstr_emp & e, const std::string & rpo, int ico);
    highfink(const fink & f, int ico);
    highfink(const manager & m, const std::string & rpo);
    highfink(const highfink & h);
    virtual void ShowAll() const;
    virtual void SetAll();
};


abstr_emp::abstr_emp() :lname("none"),fname("none"),job("none")
{
}
abstr_emp::abstr_emp(const std::string & fn, const std::string & ln,
                     const std::string & j):fname(fn),lname(ln),job(j)
{
}
abstr_emp::~abstr_emp(){}

void abstr_emp::ShowAll() const
{
    cout<<"NAME: "<<fname<<"."<<lname<<endl;
    cout<<"JOB TITLE: "<<job<<endl;
}
void abstr_emp::SetAll()
{
    cout<<"Entenr the first name: ";
    getline(cin,fname);
    cout<<"Enter the last name: ";
    getline(cin,lname);
    cout<<"Enter th job title: ";
    getline(cin,job);
}
std::ostream &operator<<(std::ostream & os, const abstr_emp & e){
    os<<"NAME: "<<e.fname<<"."<<e.lname<<endl;
    os<<"JOB TILTE: "<<e.job<<endl;
    return os;
}

employee::employee () :abstr_emp()
{
}
employee::employee(const std::string & fn, const std::string & ln,
                   const std::string & j): abstr_emp(fn,ln,j)
{
}
void employee::ShowAll() const{
    abstr_emp::ShowAll();
}
void employee::SetAll()
{
    abstr_emp::SetAll();
}

manager::manager ():abstr_emp(),inchargeof(0)
{
}
manager::manager(const std::string & fn, const std::string & ln,
                 const std::string & j, int ico ): abstr_emp(fn,ln,j),inchargeof(ico)
{
}
manager::manager(const abstr_emp & e, int ico): abstr_emp(e)
{
    inchargeof = ico;
}
manager::manager (const manager & m): abstr_emp(m)
{
    inchargeof = m.inchargeof;
}
void manager::ShowAll() const{
    abstr_emp::ShowAll();
    cout<<"IN CHARGE OF: "<<inchargeof <<endl;
}
void manager::SetAll()
{
    abstr_emp::SetAll();
    cout<<"Enter the number of in charge: ";
    cin>>inchargeof;
    while(cin.get() != '\n')
        continue;
}

fink::fink():abstr_emp(),reportsto("none")
{
}
fink::fink(const std::string & fn, const std::string & ln,
           const std::string & j, const std::string & rpo): abstr_emp(fn,ln,j),reportsto(rpo)
{
}
fink::fink(const abstr_emp & e, const std::string & rpo):abstr_emp(e),reportsto(rpo)
{
}
fink::fink(const fink & e):abstr_emp(e)
{
    reportsto = e.reportsto;
}
void fink::ShowAll() const
{
    abstr_emp::ShowAll();
    cout<<"REPORT TO: "<<reportsto<<endl;
}
void fink::SetAll()
{
    abstr_emp::SetAll();
    cout<<"Enter the reports to whom: ";
    getline(cin,reportsto);
}

highfink::highfink()
{
}
highfink::highfink(const std::string & fn, const std::string & ln,
                   const std::string & j, const std::string & rpo, int ico):
        abstr_emp(fn,ln,j),manager(fn,ln,j,ico),fink(fn,ln,j,rpo)
{
}
highfink::highfink(const abstr_emp & e, const std::string & rpo, int ico):
        abstr_emp(e),manager(e,ico),fink(e,rpo)
{
}
highfink::highfink(const fink & f, int ico):
        abstr_emp(f),fink(f),manager(f,ico)
{
}
highfink::highfink(const manager & m, const std::string & rpo):
        abstr_emp(m), manager(m),fink(m,rpo)
{

}
highfink::highfink(const highfink & h):abstr_emp(h),manager(h),fink(h)
{
}
void highfink::ShowAll() const
{
    manager::ShowAll();
    cout << "Reportsto: " << ReportsTo() << endl;
    cout << endl;

}
void highfink::SetAll()
{
    manager::SetAll();
    cout << "Enter the reportsto: ";
    getline(cin, fink::ReportsTo());

}

