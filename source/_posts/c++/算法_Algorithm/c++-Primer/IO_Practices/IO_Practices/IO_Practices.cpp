#include <iostream>
using namespace std;
class A {
public:
	A() { x = 0; cout << "Ac" << endl; }

	A(int a) { x = a;  cout << "Ac" << x << endl; }

	A(const A& a) { x = a.x;  cout << "copy A" << endl; }

	A& operator=(const A& a) { x = a.x; cout << "A=" << endl;  return *this; }

	A operator+(const A& a) { x = a.x + x;  cout << "A+" << endl;  return *this; }

	int getX() { return x; }
private:
	int x;
};
int main()
{
	A a;
	(a = a + 1) = 6;
	cout << a.getX() << endl;
	return 0;
}