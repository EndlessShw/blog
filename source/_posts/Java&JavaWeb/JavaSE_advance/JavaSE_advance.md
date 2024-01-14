---
title: JavaSE_Advance
categories:
- Java&JavaWeb
- JavaSE_Advance
tags:
- Back end
date: 2024-01-14 11:44:52
---

# JavaSE 进阶的知识

## 1. Collection 集合



## 2. 泛型



## 3. 流



## 4. 线程



## 5. 反射

### 5.1 反射机制的作用

1. 通过 java 语言中的反射机制，可以操作字节码文件(.class)

### 5.2 反射机制中涉及的重要的类

1. `java.lang.Class`：代表整个字节码文件
2. `java.lang.reflect.Method`：代表字节码中的方法字节码
3. `java.lang.reflect.Constructor`：代表字节码中的构造方法字节码
4. `java.lang.reflect.Field`：代表字节码中的属性字节码

### 5.3 获取 Class 的三种方式

1. 直接上代码：
    ```java
    public class ReflectTest {
        public static void main(String[] args) throws ClassNotFoundException {
            // 方法一：通过 Class.forName("类的全限定包名");
            // c1 代表 java.lang.String.class 字节码文件或者代表 String 类型
            Class<?> c1 = Class.forName("java.lang.String");
    
            // 方法二：Java 中任何一个对象都有 .getClass()（即 Object 的方法）
            String str = "";
            Class<? extends String> strClass = str.getClass();
            // 结果为 true，说明内存地址相同，表明 strClass 和上文的 c1 都是代表同一个东西 - 字节码文件或者代表 String 类型
            // 说明字节码文件 .class 在 JVM 中只装载一份
            System.out.println(c1 == strClass);
    
            // 方法三：Java 语言中任何一种类型，包括基本数据类型，其都有 .class 属性
            Class<String> stringClass = String.class;
        }
    }
    ```

### 5.4 通过反射实例化对象

1. 还是直接上代码
    ```java
    public class ReflectTest02 {
        public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
            Class<?> aClass = Class.forName("com.endlessshw.scanner.entity.User");
            // 从 jdk9 开始，newInstance() 方法就过时了
            // newInstance() 会调用类的无参构造方法
            // 如果没有无参构造方法，只有有参构造方法，这样实例化就会抛出实例化异常 InstantiationException
            Object o = aClass.newInstance();
            System.out.println(o);
        }
    }
    ```

### 5.5 反射机制的灵活性

1. 和常见的 `new` 实例化对象相似，但是反射机制实例化对象更加灵活，比如从配置文件中实例化对象。

### 5.6 `forName()` 的类加载

1. 使用 `forName()` 加载类时，其会调用类的静态代码块。

2. 换个思路想：如果只想加载一个类中的静态代码块，那么代码就可以这样编写：
    ```java
    try {
        Class.forName("全限定类名");
    } catch (ClassNotFoundException e) {
        e.printStackTrace();
    }
    ```

3. JDBC 使用的时候，就是这样用的。

### 5.7 路径问题

1. 一般反射的场景都需要读取文件，相对位置只在 IDEA 下有效，如果项目更改那么就找不到了，绝对路径也是。

2. 此时就需要类路径：即 src 文件夹。src 是类的根路径。

3. 获取：
    ```java
    String path = Thread.currentThread().getContextClassLoader().getResource("src | 类的根路径 下的路径").getPath();
    ```

    此时这个 `path` 打印出来，就是 src 下，一个文件的绝对路径。

4. 对于配置文件这些的，直接通过 IDEA，**复制 Source Root 就行**，但如果想要获取类文件，**最后需要把 .java 改成 .class**

5. 表面上是 src，实际上是编译后的 target/classes。**所以最终应该以 classes 文件夹为根路径**。

### 5.8 资源绑定器

1. java.util 包下提供了一个资源绑定器，便于获取属性配置文件中的内容。但要求属性配置文件必须放在类路径下。

2. 代码：
    ```java
    public class ResourceBundleTest {
        public static void main(String[] args) {
            // 资源绑定器只能绑定 xxx.properties，配置问价你必须放在类路径下。注意不写 .properties 后缀
            ResourceBundle application = ResourceBundle.getBundle("application");
            // 然后获取
            // 取代以前的 Properties.load() 和创建流读取的过程
            String value = application.getString("spring.datasource.username");
            System.out.println(value);
        }
    }
    ```

### 5.9 类加载器

1. 假设有代码：
    ```java
    String str = "abc";
    ```

    代码在开始执行之前，会将所需要类，通过类加载器，全部加载到 JVM 当中。类加载器根据上述代码，会找类对应的字节码文件（这里就是 String.class）去加载。

2. 加载方式：
    首先通过启动类加载器加载，如果加载不到（找不到对用的字节码文件），就会启动扩展类加载器去加载，再找不到就去应用类加载器

#### 5.9.1 启动类加载器

1. 启动类加载器只会加载：jre/lib/rt.jar 内的 class 字节码文件。rt.jar 中都是 JDK 中最核心的类库。

#### 5.9.2 扩展类加载器

1. 扩展类加载器只会加载：jre/lib/ext 内的 jar 包内的 class 字节码文件。ext 文件夹内中的 jar 都是扩展 jar 包。

#### 5.9.3 应用类加载器

1. 应用类加载器专门加载：classpath 中的 jar 包内的 class 文件。classpath 在系统的环境变量中有：
    ![image-20230423094455728](image-20230423094455728.png)

#### 5.9.4 双亲委派机制

1. 由加载方式的顺序可知，如果程序员自己定义了一个 String 类，那么系统还是优先选在加载 JDK 自带的 String.class。
2. 这个机制的目的就是为了保证安全。

### 5.10 通过反射获取 Field（属性/成员变量）并尝试修改其值。

1. 直接上代码：
    ```java
    public class ReflectTest03 {
        public static void main(String[] args) throws ClassNotFoundException {
            // 获取整个类
            Class<?> userClass = Class.forName("com.endlessshw.scanner.entity.User");
            // 获取类中所有的 public Field
            Field[] fields = userClass.getFields();
            // 获取类中所有的 Field
            Field[] declaredFields = userClass.getDeclaredFields();
            for (Field declaredField : declaredFields) {
                // 获取属性类型名
                Class<?> declaredFieldType = declaredField.getType();
                String declaredFieldTypeName = declaredFieldType.getName();
                System.out.println(declaredFieldTypeName);
                String declaredFieldTypeSimpleName = declaredFieldType.getSimpleName();
                System.out.println(declaredFieldTypeSimpleName);
    
                // 获取属性的修饰符
                // 返回的是数字，是修饰符的代号
                int modifiers = declaredField.getModifiers();
                String modifierStr = Modifier.toString(modifiers);
                System.out.println(modifierStr);
    
                // 现在能拿到一个 class 的修饰符、名字。其实可以反编译，通过 StringBuilder 来构建出一个类已经类中的成员的源码。
            }
        }
    }
    ```

2. 修改其值：
    ```java
    public class ReflectTest03 {
        public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException, NoSuchFieldException {
            // 获取整个类
            Class<?> userClass = Class.forName("com.endlessshw.scanner.entity.User");
            // 实例化对象
            Object user = userClass.newInstance();
            // 获取具体的 Field
            Field username = userClass.getDeclaredField("username");
            // 对应非 public 修饰的 Field，需要修改其安全属性
            username.setAccessible(true);
            // 给具体的对象的 username 属性赋值（三要素）
            username.set(user, "test");
            // 查看结果
            System.out.println(user);
            // 读取一个对象的属性值
            System.out.println(username.get(user));
        }
    }
    ```

### 5.11 反射 Method 并调用方法

1. 补充知识点：可变长参数：`属性类型... 参数名`。这个参数本质是数组。可以传多个参数，也可以传一个数组。

2. 反射 Method：
    ```java
    public class ReflectTest04 {
        public static void main(String[] args) throws ClassNotFoundException {
            Class<?> userClass = Class.forName("com.endlessshw.scanner.entity.User");
            // 获取所有的方法
            Method[] declaredMethods = userClass.getDeclaredMethods();
            // 遍历
            for (Method declaredMethod : declaredMethods) {
                // 获取方法的修饰符列表
                System.out.println(Modifier.toString(declaredMethod.getModifiers()));
                // 获取方法名
                System.out.println(declaredMethod.getName());
                // 获取方法的返回类型
                Class<?> returnType = declaredMethod.getReturnType();
                System.out.println(returnType.getName());
                // 方法的参数的类型列表
                Class<?>[] parameterTypes = declaredMethod.getParameterTypes();
                System.out.println();
                // 上述都能获取后，那么一个类中的所有方法（除了方法主体）都可以反编译出来了
            }
        }
    }
    ```

3. 调用方法：
    ```java
    // 获取某个具体的方法，第一个参数是方法名，后面可变参数就是方法的参数类型（因为对于重载方法，区分他们的方式就是通过方法名和参数列表）
    Method declaredMethod = userClass.getDeclaredMethod("setUsername", String.class);
    // 调用方法（调用某个对象的方法，传入参数，获取返回值）（四要素）
    Object returnObj = declaredMethod.invoke(userClass, "admin");
    ```


### 5.12 反射 Constructor 并调用

1. 和反射 Method 相似：
    ```java
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Class<?> userClass = Class.forName("com.endlessshw.scanner.entity.user.User");
        for (Constructor<?> declaredConstructor : userClass.getDeclaredConstructors()) {
            // 输出构造方法的修饰词 / 符
            System.out.println(Modifier.toString(declaredConstructor.getModifiers()));
            // 获取参数
            for (Class<?> parameterType : declaredConstructor.getParameterTypes()) {
                System.out.println(parameterType.getSimpleName());
            }
            System.out.println();
        }
        // 调用有参数的构造方法创建对象
        Constructor<?> declaredConstructor = userClass.getDeclaredConstructor(String.class, String.class);
        Object userWithParams = declaredConstructor.newInstance("参数1", "参数2");
    }
    ```

2. 此时就可以通过获取无参 Constructor 来创建对象，从而解决高版本 JDK 直接通过 `newInstance()` 的 Deprecated 问题。

### 5.13 其他

1. 反射还可以获取父类以及类所实现的接口。
