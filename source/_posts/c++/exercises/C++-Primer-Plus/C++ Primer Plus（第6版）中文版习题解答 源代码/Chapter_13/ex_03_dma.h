/*第十三章：编程练习 3 */
// dma.h  -- inheritance and dynamic memory allocation
#ifndef DMA_H_
#define DMA_H_
#include <iostream>

class ABC{
public:
    virtual ~ABC(){};
    virtual void View(){std::cout<<"This is ABC View(), it is empty.\n";};
};
/* 添加基类ABC，定义虚析构函数和虚View()方法，表示方法的调用对象。*/
//  Base Class Using DMA
class baseDMA : public ABC
{
private:
    char * label;
    int rating;
public:
    baseDMA(const char * l = "null", int r = 0);
    baseDMA(const baseDMA & rs);
    virtual ~baseDMA();
    virtual void View();
    /* 添加baseDMA类的View() 类方法，表示方法的调用对象。*/
    baseDMA & operator=(const baseDMA & rs);
    friend std::ostream & operator<<(std::ostream & os,
                                     const baseDMA & rs);
};

// derived class without DMA
// no destructor needed
// uses implicit copy constructor
// uses implicit assignment operator
class lacksDMA :public baseDMA
{
private:
    enum { COL_LEN = 40};
    char color[COL_LEN];
public:
    lacksDMA(const char * c = "blank", const char * l = "null",
             int r = 0);
    lacksDMA(const char * c, const baseDMA & rs);
    virtual void View();
    /* 添加lacksDMA类的View() 类方法，表示方法的调用对象。*/
    friend std::ostream & operator<<(std::ostream & os,
                                     const lacksDMA & rs);
};

// derived class with DMA
class hasDMA :public baseDMA
{
private:
    char * style;
public:
    hasDMA(const char * s = "none", const char * l = "null",
           int r = 0);
    hasDMA(const char * s, const baseDMA & rs);
    hasDMA(const hasDMA & hs);
    ~hasDMA();
    virtual void View();
    /* 添加hasDMA类的View() 类方法，表示方法的调用对象。*/
    hasDMA & operator=(const hasDMA & rs);
    friend std::ostream & operator<<(std::ostream & os,
                                     const hasDMA & rs);
};

#endif

