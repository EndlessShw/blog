/*第十六章：编程练习 10 */
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>

using namespace std;

struct Review {
    string title;
    int rating;
    int price;
    /* 添加结构成员price */
};

bool operator<(const shared_ptr<Review> & p1, const shared_ptr<Review> & p2);
bool FillReview(Review & rr);
void ShowReview(const shared_ptr<Review> & p);

bool worseThan(const shared_ptr<Review> & p1, const shared_ptr<Review> & p2);
bool expenThan(const shared_ptr<Review> & p1, const shared_ptr<Review> & p2);
/* 修改原由的worseThan()函数，参数修改为智能指针，添加 expenThan()函数 */
int main()
{
    using namespace std;

    vector<shared_ptr<Review> > books;
    Review temp;
    while(FillReview(temp))
    {
        shared_ptr<Review> pd (new Review(temp));
        /* 智能指针需要使用new动态存储一个新的对象 */
        books.push_back(pd);
    }
    if (books.size() > 0)
    {
        cout << "Choose the way to sort: "
             << "r: rate, s: rate r, p: price, d: price r, q: quit\n";
        char choice;
        while(cin >> choice && choice != 'q')
        {
            switch(choice)
            {
                case 'r': sort(books.begin(), books.end(), worseThan);
                    break;
                case 's': sort(books.rbegin(), books.rend(), worseThan);
                    break;
                case 'p': sort(books.begin(), books.end(), expenThan);
                    break;
                case 'd': sort(books.rbegin(), books.rend(), expenThan);
                    break;
                default:   sort(books.begin(), books.end());
                    break;
            }
            for_each(books.begin(), books.end(), ShowReview);
            cout << "Please choose the way to sort: "
                 << "r: rate, s: rate r, p: price, d: price r, q: quit\n";
        }
    }
    return 0;
}

bool FillReview(Review & rr)
{
    cout << "Enter book title (quit to quit): ";
    getline(cin, rr.title);
    if (rr.title == "quit" || rr.title == "")
        return false;
    cout << "Enter book rating: ";
    cin >> rr.rating;
    if (!cin)
        return false;
    cout << "Enter book price: ";
    cin >> rr.price;
    if (!cin)
        return false;
    while (cin.get()!='\n')
        continue;
    return true;
}
/* 相关函数，需要将原Review对象的方式，修改为智能指针，注意成员运算符 */
void ShowReview(const shared_ptr<Review> & p)
{
    cout << p->rating << "\t" << p->title << "\t" << p->price << endl;
}

bool operator<(const shared_ptr<Review> & p1, const shared_ptr<Review> & p2)
{
    if (p1->title < p2->title)
        return true;
    else if (p1->title == p2->title && p1->rating < p2->rating)
        return true;
    else
        return false;
}

bool worseThan(const shared_ptr<Review> & p1, const shared_ptr<Review> & p2)
{
    if (p1->rating < p2->rating)
        return true;
    else
        return false;
}

bool expenThan(const shared_ptr<Review> & p1, const shared_ptr<Review> & p2)
{
    if (p1->price < p2->price)
        return true;
    else
        return false;
}


