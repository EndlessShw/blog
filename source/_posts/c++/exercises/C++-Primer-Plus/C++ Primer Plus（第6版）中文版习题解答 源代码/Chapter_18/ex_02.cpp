/*第十八章：编程练习 2 */
#include<iostream>
#include<string>
using std::cout;
using std::endl;
class Cpmv
{
public:
    struct Info
    {
        std::string qcode;
        std::string zcode;
    };
private:
    Info *pi;
public:
    Cpmv() { pi = nullptr; cout<<"Default Constructor\n"; Display();};
    Cpmv(std::string q, std::string z);
    Cpmv(const Cpmv &cp);
    Cpmv(Cpmv &&mv);
    ~Cpmv();
    Cpmv &operator=(const Cpmv&cp);
    Cpmv &operator=(Cpmv&&mv);
    Cpmv operator+(const Cpmv &obj)const;
    void Display()const;
};

Cpmv::Cpmv(std::string q, std::string z)
{
    pi = new Info;
    pi->qcode = q;
    pi->zcode = z;
    cout<<"Constructor with args."<<endl;
    Display();
}
Cpmv::Cpmv(const Cpmv &cp)
{
    pi = new Info;
    pi->qcode = cp.pi->qcode;
    pi->zcode = cp.pi->zcode;
    cout<<"Constructor Copy."<<endl;
    Display();
}
Cpmv::Cpmv(Cpmv &&mv)
{
    cout<<"\nMove Constructor."<<endl;
    pi = mv.pi;
    mv.pi = nullptr;
}
Cpmv::~Cpmv()
{
    delete pi;
    cout<<"Deconstructor."<<endl;

}
Cpmv& Cpmv::operator=(const Cpmv&cp)
{
    if (this == &cp)
        return *this;
    delete pi;
    pi = new Info;
    pi->qcode = cp.pi->qcode;
    pi->zcode = cp.pi->zcode;
    cout<<"Assinment Normal."<<endl;
    return *this;
}
Cpmv& Cpmv::operator=(Cpmv&&mv)
{
    if (this == &mv)
        return *this;
    delete pi;
    pi = mv.pi;
    mv.pi = nullptr;
    cout<<"\nAssinment R-values."<<endl;
    Display();
    return *this;
}

Cpmv Cpmv::operator+(const Cpmv &obj) const
{
    cout<<"operator + ()."<<endl;
    return Cpmv((pi->qcode + obj.pi->qcode),(pi->zcode + obj.pi->zcode));
}

void Cpmv::Display()const
{
    cout << "Display Info: ";
    if (pi == nullptr)
        cout << "pi is null.\n";
    else
    {
        cout<<"address: "<<pi<< " qcode: " << pi->qcode
            << " zcode: " << pi->zcode << endl;
    }
}

int main()
{
    using namespace std;
    Cpmv cp1("C ","++ ");
    Cpmv cp2("Computer ", "Science ");
    Cpmv cp3 = cp2;
    cp2 = cp1;
    cp1 = cp2 + cp3;
    Cpmv cp4 (cp1 + cp2);
    return 0;
}

