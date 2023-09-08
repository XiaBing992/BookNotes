# Effective C+

## 导言

- 除非有好的理由允许隐式转换，否则声明explicit
- 拷贝构造函数和拷贝赋值操作符：如果有新对象被定义，一定会有个构造函数被调用
  ```
    class Widget
    {
    public:
        Widget();
        Widget(const Widget&rhs);
        Widget& operator=(const Widget& rhs);
    };
  
    Widget w1; //调用构造函数
    Widget w2(w1); //调用拷贝构造函数
    w1 = w2; //调用 =
  
    Widget w3 = w2; //调用拷贝构造函数
  ```

## 让自己习惯C++

### 视C++为一个语言联邦
- C++ = 'c' + 'Object-Oriented c++' + 'Template c++' + 'STL'
- 在 C 中，pass-by-value通常比pass-by-reference高效，而在C++中由于构造函数和析构函数的存在，**pass-by-reference-to**-const往往更好（和编译器层面有关，存在空指针，但没有空引用）

### 尽量以const, enum, inline 替换#define
- 获得编译错误时，#define定义的方式会带来困惑
  - 对于单纯常量，最好以const对象或enums替换#define
  - 对于形似函数的宏，最好使用inline函数替换#define

### 尽可能使用const
bitwise constess: const成员函数不能更改non-static成员变量
```
class Rational
{
  ...
};
const Rational operator* (const Rational& lhs,const Rational& rhs)
{
  ...
}

Rational a,b,c;
if(a * b = c)   //为了防止这种错误，重载加const
```

### const成员函数
这个行为编译器是允许的，因为text是一个指针，实现代码并不修改text
```
class MyClass
{
  private:
    char *text;
    //char text[10];//编译器会报错
  
  public:
    char& opeartor[](const int i) const
    {
        return text[i]; 
    }
};
```

mutable关键字：变量总是能被修改，即使是在const成员函数内。（只能作用类成员，不能与const同时使用）

### 在const和no-const成员函数中避免重复
```
class MyClass
{
public:
  const char& operator[](const int i)
  {
      ...
  }

  char& operator[](const int i)
  {
      return const_cast<char&>(
          static_cast<const MyClass&>(*this)[i]
      );
  }

};
```
- 在const成员函数中调用非const成员函数是一种危险行为，因为对象可能由此改动

### 确定对象被使用前已被初始化
- 区分成员变量的初始化与赋值
- 使用member initialization list替换赋值动作
- 基于赋值的版本会先调用default构造函数对成员变量进行初始化，然后再赋值(default -> copy)；而第二点所诉版本避免了这个问题,直接调用成员的拷贝构造(copy)

#### static对象的初始化
- static对象：定义于global、namespace、classes、函数、file作用域内被声明未static的对象
- local static：函数内的static对象
- 编译单元：产出单一目标文件的源码，基本上是单一源码文件加上所含的头文件
- c++对“定义不同编译单元内的non-local static对象”的初始化次序并无明确定义(因为决定他们的初始化顺序非常困难)

解决方法：将每个non-local static对象搬到自己的专属函数内

## 构造/析构/赋值运算

### 了解c++默默编写并调用了哪些函数
- 构造函数、copy构造、copy assignment（可能不会默认创建）、析构函数

### 若不想使用编译器自动生成的函数，就该明确而拒绝
- 声明为delete
- 将函数声明在private中，但可能被member函数和friend函数调用；可以实现一个基类这样做，实际的类在继承这个基类就可以解决这个问题

### 为多态基类声明virtual析构函数
- 任何class只要带有virtual函数都几乎可以确定应该有一个virtual析构函数
- 如果class不企图被当作base class，令其析构函数为virtual往往是个馊主意（有虚表指针，对象的体积会增加；不具有移植性，因为其他语言没有虚表）
- 一般认为，只有当class内内含至少一个virtual函数，才为它声明virtual析构函数

### 别让异常逃离析构函数
- 析构函数绝对不要吐出异常，如果一个被析构函数调用的函数可能抛出异常，析构函数应该捕捉任何异常，然后吞下它们或结束程序

### 绝不在构造和析构过程中调用virtual函数
- 在构造和析构函数期间不要调用virtual函数，因为这类调用不下降至derived class

### 令operator= 返回一个reference to *this
- 为了实现连锁赋值
```
x = y = z
```

### 在operator= 中处理"自我赋值"
```
class MyClass
{
private:
    Bitmap* pb;
    ......
};
//方式一
MyClass& Myclass::operator(const MyClass& rhs)
{
    ......
    //if(this == &rhs) return *this; //加上安全
    delete pb;//危险，rhs的pb可能和this的pb指向的是同一个值
    pb = new Bitmap(*rhs.pb);
    ......
}
//方式二
MyClass& Myclass::operator(const MyClass& rhs)
{
    ......
    Bitmap* pOrig = pb;
    pb = new Bitmap(*rhs.pb);
    delete pOrig;
    ......
}
//方式三
MyClass& widget::operator(const MyClass rhs)；
```

### 复制对象时勿忘其每一个成分
- 下面情况父类的a会被不带default构造函数（不带实参的）构造
```
class MyClass
{
private:
    int a;
    ......
};

class DerivedClass : public MyClass
{
public:
    DerivedClass& operator=(const DerivedClass rhs)
    {
        ......
    }

};
```
- 当调用一个copying函数，确保：
  1. 复制所有local成员变量
  2. 调用所有base内适当的copying函数

- 不要令copy assignment操作符调用copy构造函数（反之亦然）
- 如果copy构造函数和copy assignment函数有较多相似部分，可以建一个新的成员函数供二者调用（private: init）

## 资源管理

### 以对象管理资源

### 在资源管理类中小心copying行为
- 复制RALL对象必须一并复制它所管理的资源，一般的操作：
  1. 禁止复制
  2. 引用计数法
  3. 深拷贝
  4. 转移资源所有权

### 在资源管理类中提供对原设计资源的访问

### 成对使用new和delete时要采取相同形式
```
string *str1 = new string();
string *str2 = new string[4];

delete str1;
delete []str2;

//下面是未定义错误
//delete []str1;
//delete str2; 
```

### 以独立语句将newed对象置入智能指针
- 下面在函数参数内构造对象的行为是危险的，智能保证new MyClass的执行顺序在shared_ptr构造函数之前执行，如果priority函数抛出异常，将造成内存泄漏（与java的顺序构造不同）。使用分离语句可解决。
```
void process(shared_ptr<MyClass>(new MyClass),pritority());//危险行为
```

## 设计与声明
### 让接口容易被正确使用，不易被误用
- P78

### 设计class犹如设计type
- 如何创建和销毁
- 对象的初始化和赋值该有怎样的差别
- copying函数
- 什么是合法值
- ....

### 宁以pass-by-reference-to-const 替换pass-by-value
- pass-by-value是费时的（构造函数、析构函数、基类的构造函数、基类的析构函数）
- by reference方式传递参数可以避免slicing（对象切割）问题：当一个derived class对象以by value方式传递并被视为一个base class对象，base class对象，base class的copy构造函数会被调用，特质化性质被切割掉。

### 必须返回对象时，别妄想返回其reference
```
class Rational
{
private:
    int n,d;

public:
    const Rational operator*(const Rational& rhs);//不担心成本
    const Rational& operator*(const Rational& rhs)//由谁来析构构造的堆对象;怎么约定用户必须用引用来调用？    
    {
        Rational *r = new Rational();
        ......
    }
    
};
Rational x,y,z,p;
p = x * y * z;



```

### 将成员变量声明为private
- 语法一致性：如果public接口内的每样东西都是函数，客户就不需要再打算访问class成员时思考是否需要加小括号
- 更精确的控制：使用函数可以实现不准访问、只读访问等；
- 封装：如果使用函数访问成员变量，日后可改以某个计算替换这个替换这个成员变量，而class客服一点也不会知道class的内部实现已经发生变换
  ```
  class SpeedDate
  {
      ...
  public:
      double averageSoFar() const;
  };
  ```

### 宁以non-member、non-friend替换member函数
```
class WebBrowser
{
public:
    void clearCache();
    void clearHistory();
    void removeCookies();

    //void clearEverything();//封装性低
};

//封装性高，因为它并不增加"能够访问private函数的数量"
void clearEverything()
{
    clearCache();
    clearHistory();
    ...
}

```
- 不能只在意封装性
- 更好的做法可以让上述代码在一个命名空间内

### 若所有参数皆需要类型转换，请为此采用non-member函数
```
class Rational
{
public:
    Rational(int m=0, int n=0);
    const Rational operator*(const Rational& rhs) const;
};
Rational r1;
r = r * 2;//right
r = 2 * r;//error
```
```
const Rational operator*(const Rational& lhs, const Rational& rhs)
{
    ......
}
```

### 考虑写出一个不抛异常的swap函数
- 制造特化的swap版本
```
class WidgetImpl
{
    ......
};
class Widget
{
private:
    WidgetImpl* pImpl;
    Widget(const Widget&  rhs);
    Widget& operator(const Widget& rhs);
};

Widget w1,w2;
std::swap(w1,w2);//会复制三个Widget,三个pImpl
```
```
class WidgetImpl
{
    ......
};
class Widget
{
private:
    WidgetImpl* pImpl;
    Widget(const Widget&  rhs);
    Widget& operator(const Widget& rhs);
    void swap(Widget& other)
    {
        std::swap(a.pImpl,b.pImpl);
    }
};
namespace std{
    template<>
    void swap<Widget>(Widget& a,Widget& b)
    {
        a.swap(b);
    }
}

```
- STL容器提供有public swap成员函数和std::swap特化版本（用以调用前者）
- 类模板可以偏特化，函数模板不能偏特化
```
template<typename T>
class WidgetImpl
{
    ......
};
class Widget
{
    ......
};

//error,不能偏特化函数
template<typename T>
void swap< Wiget<T> >(Widget<T>& a,Widget& b);

//使用重载
template<typename T>
void swap(Widget<T>& a,Widget& b);
```
- 客户可以全特化std内的template，但不可以添加新的templates
```
namespace WidgetStuff{
  template<typename T>
  class WidgetImpl
  {
      ......
  };
  class Widget
  {
      ......
  };


  //使用重载
  template<typename T>
  void swap(Widget<T>& a,Widget& b);
}

```
- swap调用顺序：
  1. 先找同一命名空间
  2. 特化
  3. 非特化
```
//情况1
template<typename T>
void doSomething(T& obj1,T& obj2)
{
    swap(obj1,obj2);
}
//情况2
template<typename T>
void doSomething(T& obj1,T& obj2)
{
    using std::swap;//使编译器能看到swap命名空间
    swap(obj1,obj2);
}
//情况3
template<typename T>
void doSomething(T& obj1,T& obj2)
{
    std::swap(obj1,obj2);
}
```
实现swap总结：
1. 提供一个swap成员函数
2. 在class说在的命名空间提供一个非成员swap函数
3. 如果class非template，提供一个特化的swap函数

## 实现

### 尽可能延后变量定义式的出现时间
- 延后定义知道需要使用甚至延后到能给它初值实参为止
```
string encrypePassword(string password)
{
    string encrypted;
    if(password...)
    {
        throw ....
    }

    return encrypted;

}
```
- 循环情况，当n过大时，则应该写在外面比较高效，应该综合实际情况
```
Widget w;
for(int i=0;i<n;i++)
{
    w = ......
}
```

### 尽量少做转型动作
- C++四种转型
  - const_cast: 将对象的常量性移除
  - dynamic_cast: 安全向下转型，用于派生类转换，不能转换时，指针赋值为空
  - reinterpret_cast: 执行低级转型，重新解释指针，但没有二进制的转换，
  - static_cast: 强迫隐式转换
- 认为转型只是告诉编译器把某种类型视为另一种类型是一种错误的观念。任何一个类型转换往往令编译器编译出运行期间执行的代码
- 转型时容易写出某些似是而非的代码，下面调用的是当前对象的base class成分的副本上调用Window::onResize，然后再当前对象身上执行SpecialWindow专属动作
```
class Window
{
public:
    virtual void onResize(){...}
};
class SpecialWindow:Public Window
{
public:
    virtual void onResize()
    {
        static_cast<Window>(*this).onResize();
        ...
    }

};

```

### 避免返回handles指向对象内部成分

### 为'异常安全'而努力是值得的
- 异常安全的两个条件：
  1. 不泄露任何资源
  2. 不允许数据败坏

```
void fn(...)
{
    lock(&mutex);
    delete bgImage;
    ++imageChanges;
    bgImage = new Image();//未保证两个条件
    unlock();
}
```

- 异常安全函数提供以下三个保证之一：
  1. 基本承诺：如果异常被抛出，没有任何对象或数据结构会因此而败坏
  2. 强烈保证：如果函数成功，就是完全成功；如果函数失败，程序会恢复到调用函数之前的状态
  3. 不抛掷保证：承诺绝不抛出异常。作用于内置类型身上的所有操作都提供nothrow保证

- 一般化设计策略：copy and swap. 为打算修改的对象拷贝一个副本，然后修改，待所有改变都成功后，在做替换（有时候不切实际，如果系统内有一个函数不具备异常安全性，整个系统就不具备异常安全性）

### 透彻了解inlining的里里外外
- 调用它们不需蒙受函数调用招致的额外开销
- 可能会增加目标码大小（如果inline函数的本体很小，编译器针对‘函数本体’所产生的码可能比针对‘函数调用‘所产生的码更小）
- 函数定义在class中相当于隐喻提出inline
- 大多数编译器拒绝太过复杂的函数inline（warning）
- 编译器通常不对’通过函数指针而进行的调用‘实施inline

### 将文件间的编译依存关系降至最低
- 尽量以class声明式替换class定义式
```
//#include "date.h"  //尽量不适用定义式
class Date; //class 声明式
Date today(Date &d); //正确

```
- 为声明式和定义式提供不同的头文件

## 继承与面向对象设计

### 确定你的public继承塑模出is-a关系
- public继承意味着is-a。适用于base classes身上的每一件事情一定也适用于derived classes身上

```
class Bird
{
    public:
    virtual void fly();
};
class Penguin : public Bird
{
    public:
    virtuak void fly()
    {
        //表明企鹅是鸟，但是不会飞
        error(....);
    }
};
//另一种思想是为bird不定义fly，因为不是所有鸟都会飞
```

### 避免遮掩继承而来的名称
- 可以视为derived class作用域被嵌套在base class作用域内
![img](Effective%20C++.assets/33.jpg)
- 让遮掩的名称重见天日：
```
class Derived : public Base
{
    public:
    using Base::mf1;//所有名为mf1的函数都可见
    ......
};

```
- inline转交函数
```
class Derived : public Base
{
    public:
    void mf1(int x)
    {
        Base::mf1(x);
    }
};
```

### 区分接口继承和实现继承
- public继承由两部分组成：
  1. 函数接口继承
  2. 函数实现继承

- pure virtual函数：为了让derived classes只继承函数接口
- impure virtual函数：为了让derived classes继承该函数的接口和缺省实现
- non-virtual函数：不打算在derived class中有不同的行为

### 考虑virtual函数以外的其他选择
- 由Non-Virtual Interface手法实现Template Method模式：
  - 不实用，实际上还是使用的virtual函数
```
class GameCharacter
{
    public:
    int healthValue() const  //virtual函数的wrapper
    {
        doHealthValue();
        ....
    }

    private:
    virtual int doHealthValue() const
    {
        ...
    }
};
```

- 由Function Pointers实现Strategy模式
```
class GameCharacter;
int defaultHealthCalc(const GameCharacter& gc);
class GameCharacter
{
    public:
    typedef int (*HealthCalcFunc)(const GameCharacter&);
    explicit GameCharacter(HealthCalcFunc hcf = defaultHealthCalc)
        : healthFunc(hcf){}
    int healthValuae() const
    {
        return healthFunc(*this);
    }

    private:
    HealthCalcFunc healthFunc;
};
```
- 同一任务类型的不同实体可以有不同的健康计算函数
- 某已知人物的健康指数可以在运行期间变更
```
void setHealthCalculator(...);
```
- 存在的问题：如果需要non-public信息进行运算，就有问题

### 绝不重新定义继承而来的non-virtual函数
```
class A
{
pubilc:
    void fn();
};

class B : public A
{
public:
    void fn();
};

class *A = new B();
A->fn();
...
```

### 绝不重新定义继承而来的缺省参数值
- virtual函数是动态绑定，而缺省的参数值为静态绑定
```
class A
{
public:
    virtual void fn(int a = 10) = 0;
};

class B : public A
{
public:
    virtual void fn(int a = 5)
    {
        cout<<a<<endl;
    }
};

A *b = new B();
b.fn();//10
```

### 通过复合塑膜出has-a或“根据某物实现出”

### 明智而审慎的使用private继承
- private 继承意味着implemented-in-term-of(根据某物实现出)关系。如果D以private形式继承B，意思是D对象根据B对象实现而得，再没有其他意涵了。

```
class Timer
{
    public:
    explicit Timer(int tickFrequency);
    virtual void onTick() const;
};
```
- Widget要使用Timer的属性，如果使用public继承，Widget并不是Timer，这样做不好。可以使用private继承。
```
class Widget: private Timer
{
    private:
    virtual void onTick() const;
};
```

- 下面是另一种实现方式
```
class Widget
{
    private:
    class WidgetTimer: public Timer
    {
        public:
            virtual void OnTick() const;
    };
    WidgetTimer timer;
};
```

- c++独立对象都必须有非零大小,sizeof(Empty)大小一般为1
```
class Empty{};
```
- EBO机制（空白基类最优化）,sizeof(HoldsAnInt) == sizeof(int)
```
class HoldsAnInt: private Empty
{
    private:
    int x;
};
```

- 所以说，当面对“并不存在is-a关系的两个classes”，其中一个要访问另一个的成员，或需要重新定义其一或者多个virtual函数，private继承是一种很好的策略

### 明智而审慎的使用多重继承
```
class BorrowableItem
{
    public:
    void checkOut();
};
class ElectronicGadget
{
    private:
    bool checkOut() const;
}
mp::BorrowableItem::checkOut();//必须这样调用，否则有歧义
```
- 菱形继承的情况必须使用虚继承
```
class File{};
class InputFile: virtual public File{};
class OutputFile: virtual public File{};
class IOFile: public InputFile, public OutputFile{};
```
- 使用virtual继承的classes所产生的对象往往比non-virtual继承的兄弟们体积大；访问相应成员变量时，也比non-virtual的成员速度慢
- virtual base的初始化责任是由继承体系最底层class负责
- 忠告：
  - 非必要不适用virtul bases
  - 尽可能避免再其中放置数据，防止初始化的奇怪事情

## 模板与泛型编程

### 了解隐式接口和编译期多态
- 编译期多态：以不同的模板参数具现化导致调用不同的函数
- 运行期多态：运行期多态通过虚函数发生于运行期

### 了解typename的双重意义
- template声明式中，class 和 typename 没有什么不同
- typename必须作为嵌套从属名称的前缀词
  - 编译器在遭遇一个嵌套从属名称时，假定这个名称不是类型 
```
template<typename C>
void print2nd(const C& container)
{
    C::const_iterator* x;//到底是声明了一个迭代器还是两个数相乘
    //typename C::const_iterator* x;//right
    ......
}
```
- typename不可以出现在base classes list内的嵌套从属名称之前，也不可以在member initialization list 中尉base class修饰符
```
template<typename T>
class Derived: public Base<T>::Nested  //不允许使用
{
    public:
    explict Derived(int x): Base<T>::Nested(x)
    {
        typename Base<T>::Nested temp; //不允许使用
        ....
    }
}
```

### 学习处理模块化基类内的名称
```
//针对公司设计的类
class CompanyA
{
    public:
    void sendCleartext(const std::string& msg);
    void sendEncrypted(const std::string& msg);
}

class CompanyB
{
    public:
    void sendCleartext(const std::string& msg);
    void sendEncrypted(const std::string& msg);
}

//用于保存信息
class MsgInfo
{
    .......
};

template<typename Company>
class MsgSender
{
    public:
    void sendClear(const MsgInfo& info)
    {
        std::string msg;
        Company c;
        c.sendCleartext(msg); //right
    }
}

template<typename Company>
class LoggingMsgSender: public MsgSender<Company>
{
    public:
    void sendClearMsg(const MsgInfo& info)
    {
        sendClear(info); //无法编译
    }
}

```
- 上面代码无法通过编译的原因是基类MsgSender<Company>其中的Company是个模板参数，不到具现化的时候不知道里面有sendClear函数
  - 更清楚的说，是有可能有一个特化的MsgSender版本里面没有sendClear函数 

#### 解决办法
1. 使用this
```
template<typename Company>
class LoggingMsgSender: public MsgSender<Company>
{
    public:
    void sendClearMsg(...)
    {
        this->sendClear(info); //成立，假设sendClear被继承
    }
}
```

2. 使用using声明式
```
template<typename Company>
class LoggingMsgSender: public MsgSender<Company>
{
    using MsgSender<Company>::sendClear;//告诉编译器，假设sendClear位于base class内
    public:
    void sendClearMsg(...)
    {
        sendClear(info); //成立，假设sendClear被继承
    }
}
```

3. 明确指出被调用函数位于base class内
   - 有缺陷，当sendClear是一个virtual函数的时候 
```
template<typename Company>
class LoggingMsgSender: public MsgSender<Company>
{
    public:
    void sendClearMsg(...)
    {
        MsgSender<Company>::sendClear(info); //成立，假设sendClear被继承
    }
}
```

### 请使用traits classes表现类型信息
- traints：对内置类型和用户自定义类型表现的一样好
- 迭代器移动某个给定距离
  - 内部实现上，只有对于支持随机访问的迭代器支持+=操作，其他的迭代器只有反复施行 ++ 或者 -- 操作，共d次
```
template<typename IterT, typename DistT>
void advance(IterT& iter, DisT d);
```
- STL迭代器分类：
  1. Input迭代器：只能向前移动，模仿输入文件的读指针，只能读取且一次(如istream_iterators)
  2. Output迭代器：同上，模仿输出文件的涂写指针，只能涂写且一次(如ostream_iterators)
  3. forward迭代器：可以读或写所指物一次以上，只能向前移动
  4. Bidirectional迭代器：可以前后移动
  5. random access迭代器：随机迭代器，可以执行迭代器算数，以常量时间向前和向后跳跃(如vector, deque, string)

## 定制new 和 delete

### 了解new-handler的行为
- 当operator new抛出异常以反映一个未获满足的内存需求之前，会先调用一个客户指定的错误处理函数，即new-handler
- 为了指定调用用以内存不足的函数，客户必须调用set_new_handler
```
namespace std{
    typedef void (*new_handler)();
    new_handler set_new_handler(new_handler p) throw();
}
//需要这样使用
void outOfMem()
{
    ......
}

int main()
{
    std::set_new_handle(outOfMem);
    int* pBigDataArray = new int[1000000000];
    ......
}
```
- 卸除new-handler：将null指针传给set_new_handler

### 了解new和delete的合理替换时机
- 为什么要替换operator new 和 operator delete?
  - 用来检测运用上的错误
  - 为了强化效能：new 与 delete 主要用于一般目的；不一定对任何程序使用
  - 为了收集使用上的统计数据：收集软件如何使用动态内存   

## 杂项讨论

### 不要忽略编译器的警告

### 让自己熟悉包括TR1在内的标准程序库

### 让自己熟悉Boost
