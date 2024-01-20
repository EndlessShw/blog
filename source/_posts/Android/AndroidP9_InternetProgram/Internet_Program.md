---
title: 网络编程
categories:
- Android
- Basic principle
tags:
- Android
date: 2024-01-14 11:50:46
---

# 网络编程

## 1. Java 中的网络编程

### 1. InetAddress 类

1. 方法：

    ![图片3.png](rBsADV2pvP2AHVFGAAFTbQC7LB8027.png)

    由此可以看出，想要获取到 IP 和主机名，首先就要用到这个 InetAddress。需要注意的是函数的返回值是什么。

2. 代码实例：

    ```java
    package codes;
    
    import java.net.InetAddress;
    import java.net.UnknownHostException;
    
    public class InternetDemo {
        public static void main(String[] args) throws UnknownHostException {
    
            // 获取 InetAddress 对象
            InetAddress Ia = InetAddress.getByName("www.baidu.com");
            // 调用 InetAddress 对象中的 getHostAddress() 方法获得 IP
            String Ip = Ia.getHostAddress();
            String toString = Ia.toString();
            // 输出
            System.out.println("www.baidu.com 的 IP 地址为： " + Ip);
            System.out.println("Ia 的 toString() 为：" + toString);
    
            // 获取 InetAddress 对象
            InetAddress LocalIa = InetAddress.getLocalHost();
            // 获取 IP 地址
            String LocalIP = LocalIa.getHostAddress();
            // 或者写成
    //        LocalIP = InetAddress.getLocalHost().getHostAddress();
            // 但是该方法得不到 LAN 网卡的 IP 地址（当电脑上网卡有多个 IP 地址时）
            System.out.println("本机的 IP 地址为：" + LocalIP);
        }
    }
    ```

    结果为：

    ![image-20220204104105405](image-20220204104105405.png)



### 2. UDP

1. UDP 的 socket 是 DatagramSocket。`DatagramSocket(int port)` 创建数据包套接字并将其绑定到本地主机上的指定端口。`DatagramSocket(int port, InetAddress laddr)` 创建数据包套接字，并将其绑定到指定的本地地址的指定端口上。

    由此可知，第一个常用于接收端，绑定到本机的一个接收端口。第二个常用于发送端，发送给指定 IP 的指定端口。

2. DatagramSocket 常用的一些方法：

    ![20191018_212938.png](rBsADV2pvkyAYdCdAAB0cUg5zxw465.png)

    总结一下，当需要执行获取 IP 地址、端口以及收发有关的操作时，就涉及到 DatagramSocket 的方法。==但实际上，当想要获取到客户端的 IP 地址时，调用的时 DatagramPacket 的方法（下文提到）。==

3. 此外还需要一个类 DatagramPacket，该类的作用是将数据进行打包。常用方法如下：

    ![20191018_213001.png](rBsADV2pvmSAZXzGAAA2G9G3ynY421.png)

    上面那个用来接收，下面这个用来发送。

4. 发送端（客户端）的一般操作：

    1. 建立 DatagramSocket 服务。可以指定启动端口，也可以不指定。
    2. 将数据转成字节数组进行存储。
    3. 创建 DatagramPacket ，对数据打包并指定发送 IP 和端口。
    4. 调用 `DatagramSocket.send(DatagramPacket DP)` 发送数据。
    5. 关闭资源。

    代码实例如下：

    ```java
    package UDP;
    
    import java.io.IOException;
    import java.net.*;
    import java.nio.charset.StandardCharsets;
    
    public class UDPClient {
        public static void main(String[] args) throws IOException {
            // 创建 socket 服务，自身的服务创建在 4444 端口
            // 或者在后面指定端口也行
            DatagramSocket DS = new DatagramSocket(4444);
            // 先用字节数组将数据进行存储
            String data = "虎虎生威，虎年大吉";
            byte[] buffer = data.getBytes(StandardCharsets.UTF_8);
            // 创建 IP 地址，要将每个 10 进制 int 数转换成 byte 类型
            byte[] IP = {(byte)192, (byte)168, (byte)43, (byte)110};
            // 数据打包
            DatagramPacket DP = new DatagramPacket(buffer, buffer.length,
                    InetAddress.getByAddress(IP), 10000);
            // 发送数据
            DS.send(DP);
            // 关闭资源
            DS.close();
    
        }
    }
    ```

5. 接收端（服务端）的步骤：

    1. 建立 DatagramSocket 服务，并指定监听的端口
    2. 定义一个字节数组（缓冲区）来接收数据
    3. 创建 DatagramPacket 来接收数据
    4. 通过 DatagramPacket 的方法来获取发送方的 IP 地址。
    5. 关闭资源

    代码实例：

    ```java
    package UDP;
    
    import java.net.DatagramPacket;
    import java.net.DatagramSocket;
    
    public class UDPServer {
        public static void main(String[] args) throws Exception{
            // 创建 Datagram 服务监视端口
            DatagramSocket DS = new DatagramSocket(10000);
            // 定义一个缓冲区来接收数据
            // 可以 1024 * 64。因为一个包最大为 64k
            byte[] buffer = new byte[1024];
            DatagramPacket DP = new DatagramPacket(buffer, buffer.length);
            DS.receive(DP);
            // 获取 IP
            String IP = DP.getAddress().getHostAddress();
            System.out.println("接收到来自" + IP + "的数据是：");
            // 显示数据
            System.out.println(new String(buffer, 0, DP.getLength()));
            // 关闭资源
            DS.close();
        }
    }
    ```

6. 改进：

    1. 为服务端添加一个线程，使其不断地接收数据，并且尽量可以输入命令来停止接收
    2. 发送端通过 bufferedReader 来获取键盘输入，通过循环可以多次输入。

    实例代码：

    1. 发送端（客户端）：

        ```java
        package UDP;
        
        import java.io.BufferedReader;
        import java.io.IOException;
        import java.io.InputStreamReader;
        import java.net.DatagramPacket;
        import java.net.DatagramSocket;
        import java.net.InetAddress;
        import java.nio.charset.StandardCharsets;
        
        public class UDPChatClientThread{
            public static void main(String[] args) {
                // 创建 DatagramSocket
                DatagramSocket DS = null;
                BufferedReader BR = null;
                try{
                    if (DS == null) {
                        DS = new DatagramSocket(10001);
                    }
                    // 键盘读取
                    if (BR == null) {
                        BR = new BufferedReader(new InputStreamReader(System.in));
                    }
                    // 读取键盘输入
                    String inputLine = null;
                    byte[] IP = {(byte)192, (byte)168, (byte)43, (byte)110};
                    while(!(inputLine = BR.readLine()).equals("quit")){
                        // 发送数据，一行一行输入
                        byte[] buffer = inputLine.getBytes(StandardCharsets.UTF_8);
                        DatagramPacket DP = new DatagramPacket(buffer, buffer.length, InetAddress.getByAddress(IP), 10000);
                        DS.send(DP);
                    }
                }
                catch (Exception e){
                    System.out.println("数据发送失败");
                }
                finally {
                    if (DS != null) {
                        DS.close();
                    }
                    if (BR != null) {
                        try {
                            BR.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        ```

    2. 接收端（服务端）

        ```java
        package UDP;
        
        import java.net.DatagramPacket;
        import java.net.DatagramSocket;
        import java.util.Scanner;
        
        public class UDPChatServerThread implements Runnable{
        
            public volatile boolean exit = false;
        
            @Override
            public void run() {
                while(!exit){
                    DatagramSocket DS = null;
                    try{
                        if (DS == null) {
                            DS = new DatagramSocket(10000);
                        }
                        // 创建缓冲区
                        byte[] buffer = new byte[1024];
                        // 将接收到的数据打包
                        DatagramPacket DP = new DatagramPacket(buffer, buffer.length);
                        DS.receive(DP);
                        // 获取 IP
                        String IP = DP.getAddress().getHostAddress();
                        // 输出数据
                        System.out.println(IP + ":" + new String(buffer, 0, DP.getLength()));
                    }
                    catch (Exception e){
                        System.out.println("接收数据错误！");
                        e.printStackTrace();
                    }
                    finally {
                        if (DS != null) {
                            DS.close();
                        }
                    }
                }
            }
        
            public static void main(String[] args) {
                UDPChatServerThread udpChatServerThread = new UDPChatServerThread();
                Thread chatServerThread = new Thread(udpChatServerThread);
                chatServerThread.start();
                Scanner inputScanner = new Scanner(System.in);
                String quit = "start";
                while(!quit.equals("quit")){
                    quit = inputScanner.next();
                }
                // 用标志位来关闭服务
                udpChatServerThread.exit = true;
            }
        }
        ```

    结果：

    ![image-20220204153135000](image-20220204153135000.png)

    ![image-20220204153156725](image-20220204153156725.png)

    实际上接收端还需要接收一次数据才能停止服务。

    

### 3. TCP

1. TCP 在创建 Socket 服务时，和 UDP 稍微不同。在 TCP 中，客户端创建 Socket 服务，而服务端创建的服务是 ServerSocket。同时，ServerSocket 会调用 `accept()` 方法来阻塞式监听连接到自己的 Socket 并且接收。该方法返回一个 Socket。

2. Socket 的常用方法：

    ![20191018_213250.png](rBsADV2pvw6AHmrdAACo1-GXUy0496.png)

3. 发送端：

    1. 创建 Socket 服务，指定其服务端的主机和端口号。（DatagramSocket 是指定本机的使用端口，发送方和接收方都要指定）
    2. 将要发送的数据用字节数组保存
    3. 获取 Socket 的输出流，利用输出流（调用 `OutputStream.write(byte[] buffer)` ）将数据发送。
    4. 关闭输入流
    5. 获取 Socket 的输入流，通过调用 `InputStream.read(byte[] buffer)` 来获取反馈的信息。
    6. 打印，然后关闭 Socket

    代码：

    ```java
    package TCP;
    
    import java.io.IOException;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.net.InetAddress;
    import java.net.Socket;
    import java.nio.charset.StandardCharsets;
    
    public class TCPClient {
        public static void main(String[] args) {
            // 创建 socket 服务
            Socket socket = null;
            try{
                if (socket == null) {
                    byte[] IP = {(byte)192, (byte)168, (byte)43, (byte)110};
                    socket = new Socket(InetAddress.getByAddress(IP), 20000);
                }
                // 把字符串数据转换成字节数组
                byte[] buffer = "虎年大吉，虎虎生威".getBytes(StandardCharsets.UTF_8);
    
                // 获取 socket 的输出流
                OutputStream outputStream = socket.getOutputStream();
                // 发送数据
                outputStream.write(buffer);
                // 发送完成后关闭输出流
                socket.shutdownOutput();
    
                // 获取输入流，获得反馈的信息
                InputStream inputStream = socket.getInputStream();
                byte[] feedbackBuffer = new byte[1024];
                // 通过输入流读取反馈信息并将其存储在缓冲区中，然后获取写入的长度
                int length = inputStream.read(feedbackBuffer);
                // 打印反馈信息
                System.out.println(new String(feedbackBuffer, 0, length));
                // 接收完毕后关闭输入流
                socket.shutdownInput();
            }
            catch (Exception e){
                System.out.println("数据传输失败");
                e.printStackTrace();
            }
            finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
    ```

4. 服务端（接收端）

    1. 创建 ServerSocket 服务并指定端口，调用 `ServerSocket.accept()` 方法来接收 Socket。
    2. 获得对方的 IP 地址
    3. 获取输入流，建立缓冲区，通过 `InputStream.read(byte[] butter)` 来获得输入流的内容。
    4. 关闭输入流。
    5. 获取输出流，发送反馈信息。
    6. 关闭 Socket 和 ServerSocket、

    代码实现：

    ```java
    package TCP;
    
    import java.io.IOException;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.net.ServerSocket;
    import java.net.Socket;
    import java.nio.charset.StandardCharsets;
    
    public class TCPServer {
        public static void main(String[] args) throws IOException {
            // 创建 ServerSocket 服务
            ServerSocket SS = new ServerSocket(20000);
            // 阻塞式监听端口并接收 socket
            Socket socket = SS.accept();
    
            // 获取对方的 IP 地址
            String IP = socket.getInetAddress().getHostAddress();
            // 输出对方的信息
            System.out.println(IP + "-----connected.");
    
            // 获取输入流
            InputStream inputStream = socket.getInputStream();
            // 创建缓冲区
            byte[] buffer = new byte[1024];
            int length = 0;
            // 缓冲区存储输入流内容
            while((length = inputStream.read(buffer)) != -1){
                // 将获取到的内容打印
                System.out.println(new String(buffer, 0, length));
            }
            // 关闭输入流
            socket.shutdownInput();
    
            // 发送反馈信息
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write("服务端收到了您的信息".getBytes(StandardCharsets.UTF_8));
    
            // 关闭资源
            socket.shutdownOutput();
            socket.close();
            SS.close();
        }
    
    }
    
    ```

5. 结果：

    ![image-20220204160457492](image-20220204160457492.png)

    ![image-20220204161830090](image-20220204161830090.png)

6. 注意

    需要注意的是，在本机通过 `InetAddress.getByName(String Hostname, int port)` 创建 Socket 时。由于主机有多块网卡。所以通过主机名来获取 IP 时，可能会获取到其他网卡（例如虚拟机）。一般的做法是遍历所有的网卡拿到 IP 列表，然后选择。





## 2. Android 中的网络编程（用 Java 的 Api 写）

### 1. 使用 Java 的 Api 请求数据并处理

1. 请求样例：

    ![image-20220213115113266](image-20220213115113266.png)
    
1. 通过 http 协议访问、获取内容并且最后进行数据处理 --- `loadJson()`：

    ```java
    // shift + ctrl + 回车 自动补全括号或者封号
    public void loadJson(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                // ctrl + p 显示函数要求的参数
                try {
                    URL url = new URL("http://192.168.43.110:9102/get/text");
                    HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                    // 超时时间为 10s
                    httpURLConnection.setConnectTimeout(10000);
                    // 请求方式为 get
                    httpURLConnection.setRequestMethod("GET");
                    // 设置 http 请求包的请求头的一些参数和值
                    httpURLConnection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
                    httpURLConnection.setRequestProperty("Accept", "*/*");
                    httpURLConnection.connect();
                    // 获取结果码
                    int responseCode = httpURLConnection.getResponseCode();
                    if (responseCode == 200) {
                        // 将 http 返回包的头部的信息用 Map （键值对）进行存储
                        Map<String, List<String>> headerFields = httpURLConnection.getHeaderFields();
                        Log.d(TAG, headerFields.toString());
                        // 将 Map 中的所有键值对存储到 Set 里面，Set 的每一个元素都是一个 Entry。
                        // Java 中用 Entry 内部类表示一个映射项（类似一个小 Map）。包含 getKey() 和 getValue() 方法
                        Set<Map.Entry<String, List<String>>> entries = headerFields.entrySet();
                        // entries.for 来快捷遍历
                        // 将 http 响应头的所有内容打印出来
                        for (Map.Entry<String, List<String>> entry : entries) {
                            Log.d(TAG, entry.getKey() + " == " + entry.getValue());
                        }
                        
                        // 通过获取返回包内容，可以看出他返回的是一个输入流
                        // 内容为：buffer(com.android.okhttp.internal.http.Http1xStream$ChunkedSource@c6cf62a).inputStream()
                          Object content = httpURLConnection.getContent();
                          Log.d(TAG, "content --> " + content);
                        InputStream inputStream = httpURLConnection.getInputStream();
                        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                        // 读取到输入流内容
                        String json = bufferedReader.readLine();
                        //Log.d(TAG, "json --> " + json);
                        Gson gson = new Gson();
                        // fromJson 将指定的 json 格式内容转换成指定类的一个具体对象
                        GetTextItem getTextItem = gson.fromJson(json, GetTextItem.class);
                        updateUI(getTextItem);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
        
    /**
     * UI 更新不能在子线程
     *
     * @param getTextItem
     */
    private void updateUI(GetTextItem getTextItem) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                mGetResultListAdapter.setData(getTextItem);
            }
        });
    }
    ```

    在 Android Api > 27 以后，对 http 的访问，在 AndroidManifest.xml 的 `<application>` 中，要么添加字段 `android:usesCleartextTraffic="true"`。要么添加网络安全配置文件 `network_security_config.xml`。

2. 根据获取到的 json 内容，右键 --> Generate --> GsonFormatPlus。将 Json 转换成一个大的实体类。

    ```java
    package com.example.androidnetworkdemo.domain;
    
    import java.util.List;
    
    public class GetTextItem {
    
        private Boolean success;
        private Integer code;
        private String message;
        private List<DataBean> data;
    
        public Boolean getSuccess() {
            return success;
        }
    
        public void setSuccess(Boolean success) {
            this.success = success;
        }
    
        public Integer getCode() {
            return code;
        }
    
        public void setCode(Integer code) {
            this.code = code;
        }
    
        public String getMessage() {
            return message;
        }
    
        public void setMessage(String message) {
            this.message = message;
        }
    
        public List<DataBean> getData() {
            return data;
        }
    
        public void setData(List<DataBean> data) {
            this.data = data;
        }
    
        public static class DataBean {
            private String id;
            private String title;
            private Integer viewCount;
            private Integer commentCount;
            private String publishTime;
            private String userName;
            private String cover;
    
            public String getId() {
                return id;
            }
    
            public void setId(String id) {
                this.id = id;
            }
    
            public String getTitle() {
                return title;
            }
    
            public void setTitle(String title) {
                this.title = title;
            }
    
            public Integer getViewCount() {
                return viewCount;
            }
    
            public void setViewCount(Integer viewCount) {
                this.viewCount = viewCount;
            }
    
            public Integer getCommentCount() {
                return commentCount;
            }
    
            public void setCommentCount(Integer commentCount) {
                this.commentCount = commentCount;
            }
    
            public String getPublishTime() {
                return publishTime;
            }
    
            public void setPublishTime(String publishTime) {
                this.publishTime = publishTime;
            }
    
            public String getUserName() {
                return userName;
            }
    
            public void setUserName(String userName) {
                this.userName = userName;
            }
    
            public String getCover() {
                return cover;
            }
    
            public void setCover(String cover) {
                this.cover = cover;
            }
        }
    }
    ```

3. 用 RecyclerView 将获取到的数据显示出来

    1. item_get_text.xml：

        ```xml
        <?xml version="1.0" encoding="utf-8"?>
        <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:orientation="horizontal">
        
            <ImageView
                android:id="@+id/item_image"
                android:layout_width="90dp"
                android:layout_height="90dp"
                android:background="#99ff00"
                android:scaleType="centerCrop" />
        
            <LinearLayout
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:orientation="vertical">
        
                <!-- lines = "1" 表示只占用一行 -->
                <!-- ellipsize = "end" 表示显示不下的用省略号代替 -->
                <TextView
                    android:id="@+id/item_title"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:layout_margin="10dp"
                    android:ellipsize="end"
                    android:lines="1"
                    android:text="我是标题"
                    android:textSize="18sp" />
        
                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:layout_marginTop="10dp"
                    android:orientation="horizontal">
        
                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:layout_marginLeft="10dp"
                        android:text="作者名" />
        
                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:layout_marginLeft="10dp"
                        android:text="查看数" />
        
                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:layout_marginLeft="10dp"
                        android:text="评论数" />
        
                </LinearLayout>
        
            </LinearLayout>
        
        </LinearLayout>
        ```

        ![image-20220211174252555](image-20220211174252555.png)

    2. 初始化控件以及设置布局管理器和 adapter：

        ```java
        private void initView() {
            // 利用 RecyclerView 显示 Json 数据
            RecyclerView recyclerView = this.findViewById(R.id.result_list);
            recyclerView.setLayoutManager(new LinearLayoutManager(this));
            // 为 RecyclerView 添加 item 装饰器（这里的目的是增加每个 item 之间的空隙）
            recyclerView.addItemDecoration(new RecyclerView.ItemDecoration() {
                
                /**
                 * Retrieve any offsets for the given item. Each field of <code>outRect</code> specifies
                 * the number of pixels that the item view should be inset by, similar to padding or margin.
                 *
                 * @param outRect
                 * @param view
                 * @param parent
                 * @param state
                 */
                @Override
                public void getItemOffsets(@NonNull @NotNull Rect outRect, @NonNull @NotNull View view, @NonNull @NotNull RecyclerView parent, @NonNull @NotNull RecyclerView.State state) {
                    outRect.top = 5;
                    outRect.bottom = 5;
                }
            });
            mGetResultListAdapter = new GetResultListAdapter();
            recyclerView.setAdapter(mGetResultListAdapter);
            recyclerView.setItemViewCacheSize(200);
        }
        ```

    3. 创建 adapter --- GetResultListAdapter.java：

        ```java
        package com.example.androidnetworkdemo.adapters;
        
        import android.icu.text.Transliterator;
        import android.util.Log;
        import android.view.LayoutInflater;
        import android.view.View;
        import android.view.ViewGroup;
        import android.widget.ImageView;
        import android.widget.TextView;
        
        import androidx.annotation.NonNull;
        import androidx.recyclerview.widget.RecyclerView;
        
        import com.bumptech.glide.Glide;
        import com.example.androidnetworkdemo.R;
        import com.example.androidnetworkdemo.domain.GetTextItem;
        
        import org.jetbrains.annotations.NotNull;
        import org.w3c.dom.Text;
        
        import java.util.ArrayList;
        import java.util.List;
        
        public class GetResultListAdapter extends RecyclerView.Adapter<GetResultListAdapter.InnerHolder> {
        
            private static final String TAG = "GetResultListAdapter";
            // 假设直接获取 GetTextItem.data，当其置空时会这类会容易崩溃
            private List<GetTextItem.DataBean> mData = new ArrayList<>();
            private TextView mTitleTextView;
            private ImageView mImageView;
            private int mPosition;
        
            @NonNull
            @org.jetbrains.annotations.NotNull
            @Override
            public InnerHolder onCreateViewHolder(@NonNull @org.jetbrains.annotations.NotNull ViewGroup parent, int viewType) {
                View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_get_text, parent, false);
                return new InnerHolder(itemView);
            }
        
            @Override
            public void onBindViewHolder(@NonNull @org.jetbrains.annotations.NotNull GetResultListAdapter.InnerHolder holder, int position) {
                // 获取数据列表中的单个元素，这里也就是键 "data" 的其中一个值。
                mPosition = position;
                GetTextItem.DataBean dataBean = mData.get(position);
                mTitleTextView.setText(dataBean.getTitle());
            }
        
            @Override
            public int getItemCount() {
                return mData.size();
            }
        
            public void setData(GetTextItem getTextItem) {
                mData.clear();
                // 获取返回的数据
                // 由返回的 json 数据可知，键为 "data" 的值是数据，里面包含图片，标题、作者等各种信息。
                // data 在 getTextItem 类中的类型是 List<JavaBean>
                mData.addAll(getTextItem.getData());
                // 通知数据已经发生改变
                notifyDataSetChanged();
            }
        
            public class InnerHolder extends RecyclerView.ViewHolder {
                public InnerHolder(@NonNull @NotNull View itemView) {
                    super(itemView);
                    mTitleTextView = itemView.findViewById(R.id.item_title);
                    mImageView = itemView.findViewById(R.id.item_image);
                    // 获取到图片的指定路径，然后用 Glide 图片框架
                    Glide.with(itemView.getContext()).load("http://192.168.43.110:9102" +
                            mData.get(mPosition).getCover()).into(mImageView);
                    Log.d(TAG, "Cover is " + mData.get(mPosition).getCover());
                }
            }
        }
        ```

4. 结果显示

    ![image-20220211175022093](image-20220211175022093.png)



### 2. 利用 Java Api 获取网络图片

1. 创建一个按钮控件和一个显示图片的控件 --- activity_pic_load.xml

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout
        xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        xmlns:tools="http://schemas.android.com/tools"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        tools:context=".PicLoadActivity"
        android:orientation="vertical">
    
        <Button
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:onClick="loadPic"
            android:text="loadPic"
            android:textAllCaps="false" />
    
        <ImageView
            android:id="@+id/result_image"
            android:layout_width="match_parent"
            android:layout_height="match_parent" />
    
    </LinearLayout>
    ```

    ![image-20220211175339127](image-20220211175339127.png)

2. 按钮触发方法 --- `loadPic()` ：

    ```java
    public void loadPic(View view) {
            new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    URL url = new URL("https://imgs.sunofbeaches.com/group1/M00/00/02/rBPLFV1x6Q2AMjxyAADy5tr458c500.jpg");
                    HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                    // 超时时间为 10s
                    httpURLConnection.setConnectTimeout(10000);
                    // 请求方式为 get
                    httpURLConnection.setRequestMethod("GET");
                    // 设置 http 请求包的请求头的一些参数和值
                    httpURLConnection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
                    httpURLConnection.setRequestProperty("Accept", "*/*");
                    httpURLConnection.connect();
                    
                    int responseCode = httpURLConnection.getResponseCode();
                    Log.d(TAG, "responseCode === " + responseCode);
                    if (responseCode == HttpURLConnection.HTTP_OK) {
                        // 获取返回数据的输入流
                        InputStream inputStream = httpURLConnection.getInputStream();
                        // 转成 Bitmap
                        final Bitmap bitmap = BitmapFactory.decodeStream(inputStream);
                        // 更新 UI，要在主线程里面。或者用 View.post() 方法也行（本质也是使用 Handler.post）
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                ImageView imageView = findViewById(R.id.result_image);
                                // 将获取到的 bitmap 设置到 layout 上显示
                                imageView.setImageBitmap(bitmap);
                            }
                        });
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
    ```



### 3. 对超大图片的简易处理

1. 当获取到的图片很大时（例如 20 MB 的图片），如果手机的性能不行，那么就会导致 OOM(Out Of Memory)的发生。因此，对于获取到的图片，当大于一定的大小时，需要对其进行一些处理。

2. 代码：

    ```java
    public void loadPic(View view) {
        
        // 当图片过大时，加载中如果手机性能不足，会导致应用崩溃
        BitmapFactory.Options options = new BitmapFactory.Options();
        final Bitmap bigImage = BitmapFactory.decodeResource(getResources(), R.mipmap.big_image, options);
        ImageView imageView = findViewById(R.id.result_image);
        // 设置图片的压缩比例，即分辨率原图片的几分之一
        // 实际上，压缩比例不能写死，因此要根据控件的大小动态变化
        options.inSampleSize = 2;
        
        // 值设为 true，内存不加载，那么将不返回实际的 bitmap，也不给其分配内存空间这样就避免内存溢出了。
        // 但是允许我们查询图片的信息这其中就包括图片大小信息
        options.inJustDecodeBounds = true;
        
        // 动态设置 inSampleSize
        // 拿到图片宽度
        int outWidth = options.outWidth;
        // 在涉及数值的地方打 Log 查看
        Log.d(TAG, "outWidth === " + outWidth);
        // 拿到图片高度
        int outHeight = options.outHeight;
        Log.d(TAG, "outHeight === " + outHeight);
        // 拿到控件的尺寸
        int measuredWidth = imageView.getMeasuredWidth();
        Log.d(TAG, "imageView.Width === " + measuredWidth);
        int measuredHeight = imageView.getMeasuredHeight();
        Log.d(TAG, "imageView.Height === " + measuredHeight);
        
        // 图片的宽度 / 控件的宽度
        // 图片的高度 / 控件的高度
        // 然后取两者最大值
        // 如果图片小于控件大小，那默认为 1
        if (outHeight > measuredHeight || outWidth > measuredWidth) {
            int ratioHeight = outHeight / measuredHeight;
            int ratioWeight = outWidth / measuredWidth;
            options.inSampleSize = Math.max(ratioHeight, ratioWeight);
            Log.d(TAG, "inSampleSize === " + options.inSampleSize);
        }
        
        // 或者调用他人算法
        options.inSampleSize = calculateInSampleSize(options, measuredWidth, measuredHeight);
        Log.d(TAG, "inSampleSize === " + options.inSampleSize);
        
        // 设置回来以在内存中进行图片加载
        options.inJustDecodeBounds = false;
        
        // 将获取到的 bitmap 设置到 layout 上显示
        imageView.setImageBitmap(bigImage);
    }
    
    /**
     * 处理大图片算法，来自 https://www.sunofbeach.net/a/1201092087920054272
     *
     * @param options
     * @param maxWidth
     * @param maxHeight
     * @return
     */
    public static int calculateInSampleSize(BitmapFactory.Options options, int maxWidth, int maxHeight) {
        //这里其实是获取到默认的高度和宽度，也就是图片的实际高度和宽度
        final int height = options.outHeight;
        final int width = options.outWidth;
        //默认采样率为1，也就是不变嘛。
        int inSampleSize = 1;
        //===============核心算法啦====================
        if (width > maxWidth || height > maxHeight) {
            if (width > height) {
                inSampleSize = Math.round((float) height / (float) maxHeight);
            } else {
                inSampleSize = Math.round((float) width / (float) maxWidth);
            }
            final float totalPixels = width * height;
            final float maxTotalPixels = maxWidth * maxHeight * 2;
            while (totalPixels / (inSampleSize * inSampleSize) > maxTotalPixels) {
                inSampleSize++;
            }
        }
        //=============核心算法end================
        return inSampleSize;
    }
    ```



### 4. 用 POST 方式提交评论

1. 根据服务器提供的方法。请求的主体部分是一个 json 字段，然后给出了样例。

2. 写一个按钮负责发起提交事件 --- activity_post_comment.xml

3. 大致的思路为：

    1. 发起 Post 请求
    2. 根据给的例子，将 json 用 GsomFormatPlus 转成 JavaBean 类。
    3. 创建该类，实例化这个 JavaBean 类并设置 json 中的值。再将其转回 json 格式，然后让输出流输出它。
    4. 获取响应码

4. 请求样例：

    ![image-20220213115021562](image-20220213115021562.png)

5. PostCommentActivity.java：

    ```java
    package com.example.androidnetworkdemo;
    
    import androidx.appcompat.app.AppCompatActivity;
    
    import android.os.Bundle;
    import android.util.Log;
    import android.view.View;
    
    import com.example.androidnetworkdemo.domain.CommentItem;
    import com.google.gson.Gson;
    
    import java.io.BufferedReader;
    import java.io.IOException;
    import java.io.InputStream;
    import java.io.InputStreamReader;
    import java.io.OutputStream;
    import java.net.HttpURLConnection;
    import java.net.MalformedURLException;
    import java.net.URL;
    import java.nio.charset.StandardCharsets;
    
    public class PostCommentActivity extends AppCompatActivity {
    
        private static final String TAG = "PostCommentActivity";
    
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_post_comment);
        }
    
        public void postComment(View view) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    // 放在外面，防止内存泄露
                    OutputStream outputStream = null;
                    InputStream inputStream = null;
                    BufferedReader bufferedReader;
    
                    try {
                        // 发起 Post 请求
                        URL url = new URL("http://192.168.43.110:9102/post/comment");
                        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                        httpURLConnection.setRequestMethod("POST");
                        httpURLConnection.setConnectTimeout(10000);
                        // setRequestProperty() 的参数参考抓包软件抓的包
                        httpURLConnection.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
                        httpURLConnection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
                        httpURLConnection.setRequestProperty("Accept", "application/json, text/plain, */*");
    
                        // 实例化提交评论的 json 转实体的类
                        CommentItem commentItem = new CommentItem("123456789", "我是评论的内容");
                        Gson gson = new Gson();
                        // 将对象转成 json 格式传输
                        String jsonStr = gson.toJson(commentItem);
                        byte[] jsonStrBytes = jsonStr.getBytes(StandardCharsets.UTF_8);
                        // valueOf() 将其他类型的数据转成字符串型
                        // Content-Length 指示出报文中主体部分的字节大小，他表示的是字节的数目，因此这里要用 byte[] 的长度而不是 String 的长度
                        Log.d(TAG, "jsonStrByte.length === " + jsonStrBytes.length);
                        httpURLConnection.setRequestProperty("Content-Length", String.valueOf(jsonStrBytes.length));
    
                        // 连接
                        httpURLConnection.connect();
    
                        // 把数据写到服务器中（获取输出流）
                        outputStream = httpURLConnection.getOutputStream();
                        // 将数据写入(流的写入是用 byte[]
                        outputStream.write(jsonStrBytes);
                        outputStream.flush();
    
                        // 写完后要拿结果
                        // 获取返回响应码
                        int responseCode = httpURLConnection.getResponseCode();
                        if (responseCode == HttpURLConnection.HTTP_OK) {
                            inputStream = httpURLConnection.getInputStream();
                            bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                            // 这里只读取了一行（因为他返回的主体内容也就一行）
                            Log.d(TAG, "result is " + bufferedReader.readLine());
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }finally {
                        if (outputStream != null) {
                            try {
                                outputStream.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        if (inputStream != null) {
                            try {
                                inputStream.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }).start();
        }
    }
    ```



### 5. URL 带参数的请求

1. get 和 post 一样。

2. 核心逻辑就是在请求的 URL 上添加参数（键值对）

3. 请求样例

    ![image-20220213115001498](image-20220213115001498.png)

4. 代码：

    ```java
    /**
     * 发起带参数的 get 请求
     * @param view
     */
    public void getRequestWithParams(View view) {
        Map<String, String> params = new HashMap<>();
        params.put("keyword", "这是关键字");
        params.put("page", "12");
        params.put("order", "0");
        // 发起请求
        startRequest(params, "GET", "/get/param");
    }
    
    /**
     * get 和 post 请求方式大致相同，重构成一个方法
     *
     * @param params        请求的参数（字典形式）
     * @param requestMethod 请求方式，GET 或者 POST
     * @param api           接口值（开头要加 "\" )
     */
    private void startRequest(Map<String, String> params, String requestMethod, String api) {
        new Thread(new Runnable() {
            private StringBuilder mStringBuilder = null;
            InputStream inputStream = null;
            BufferedReader bufferedReader = null;
            
            @Override
            public void run() {
                try {
                    // 组装参数，请求的时候可以有不带任何参数的 URL
                    if (params != null && params.size() > 0) {
                        mStringBuilder = new StringBuilder("?");
                        // 将字典中每一个键值对都变成集合的一个元素，然后用迭代器迭代，或者将 entrySet 取出，用 foreach 遍历
                        Iterator<Map.Entry<String, String>> entryIterator = params.entrySet().iterator();
                        while (entryIterator.hasNext()) {
                            Map.Entry<String, String> next = entryIterator.next();
                            // 将键值对以 "键=值" 的字符串形式保存
                            mStringBuilder.append(next.getKey());
                            mStringBuilder.append("=");
                            mStringBuilder.append(next.getValue());
                            // 如果当前的键值对不是最后一个，那么需要在值的后面添加一个 "&" 用来拼接下一个键值对
                            if (entryIterator.hasNext()) {
                                mStringBuilder.append("&");
                            }
                        }
                        Log.d(TAG, "stringBuilder is " + mStringBuilder.toString());
                    }
                    URL url;
                    if (mStringBuilder != null) {
                        String paramsString = mStringBuilder.toString();
                        url = new URL(BASE_URL + api + "/" + paramsString);
                    } else {
                        url = new URL(BASE_URL + api);
                    }
                    Log.d(TAG, "url is " + url.toString());
                    
                    HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                    httpURLConnection.setRequestMethod(requestMethod);
                    httpURLConnection.setConnectTimeout(10000);
                    // setRequestProperty() 的参数参考抓包软件抓的包
                    httpURLConnection.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
                    httpURLConnection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
                    httpURLConnection.setRequestProperty("Accept", "application/json, text/plain, */*");
                    httpURLConnection.connect();
                    // 默认为 true
                    httpURLConnection.setDoInput(true);
                    // 默认为 false，因此需要开启
                    httpURLConnection.setDoOutput(true);
                    
                    // 获取响应结果
                    int responseCode = httpURLConnection.getResponseCode();
                    if (responseCode == HttpURLConnection.HTTP_OK) {
                        inputStream = httpURLConnection.getInputStream();
                        bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                        // 这里只读取了一行（因为他返回的主体内容也就一行）
                        Log.d(TAG, "result is " + bufferedReader.readLine());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        bufferedReader.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }
    
    /**
     * 发起带参数的 post 请求
     * @param view
     */
    public void postRequestWithParams(View view) {
        Map<String, String> params = new HashMap<>();
        params.put("string", "这是我的字符串内容");
        // 发起请求
        startRequest(params, "POST", "/post/string");
    }
    ```



### 6. 单文件上传

1. 单文件上传的关键在于 http 包主体内容的实现。可以用 postman 来实现单文件上传，然后用抓包软件抓包，查看格式。

2. 主体格式：

    ![image-20220213114714398](image-20220213114714398.png)

    ![image-20220213114736347](image-20220213114736347.png)

    

3. 请求样例：

    ![image-20220213114856405](image-20220213114856405.png)

4. 代码 --- `postFile(View view)` ：

    ```java
    /**
     * 上传单个文件
     * 注意，上传文件的时候，建议先抓个包查看格式，然后尽量完全仿照格式来写
     *
     * @param view
     */
    public void postFile(View view) {
        // TODO: 抽取方法，完成上传多个文件
        new Thread(new Runnable() {
            @Override
            public void run() {
                File file = new File("/storage/emulated/0/Download/904413721286148096.png");
                String fileKey = "file";
                String fileName = file.getName();
                String fileType = null;
                try {
                    fileType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(MimeTypeMap.getFileExtensionFromUrl(file.toURI().toURL().toString()));
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                }
                Log.d(TAG, "fileType is " + fileType);
                String BOUNDARY = "--------------------------481790588201105611341721";
                OutputStream outputStream = null;
                BufferedReader bufferedReader = null;
                BufferedInputStream bufferedInputStream = null;
                InputStream inputStream = null;
                try {
                    URL url = new URL(BASE_URL + "/file/upload");
                    HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                    httpURLConnection.setRequestMethod("POST");
                    httpURLConnection.setConnectTimeout(10000);
                    httpURLConnection.setRequestProperty("User-Agent", "Android/" + Build.VERSION.SDK_INT);
                    httpURLConnection.setRequestProperty("Accept", "*/*");
                    // 等同于 httpURLConnection.setUseCaches(false);
                    httpURLConnection.setRequestProperty("Cache-Control", "no-cache");
                    httpURLConnection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + BOUNDARY);
                    httpURLConnection.setRequestProperty("Connection", "keep-alive");
                    // 默认为 true
                    httpURLConnection.setDoInput(true);
                    // 默认为 false，因此需要开启
                    httpURLConnection.setDoOutput(true);
                    httpURLConnection.connect();
                    Log.d(TAG, "connection established");
                    
                    // 获取输出流
                    outputStream = httpURLConnection.getOutputStream();
                    
                    // 准备发送数据的头部数据（是 http 中主体部分的）
                    StringBuilder headerInfoSB = new StringBuilder();
                    headerInfoSB.append("--");
                    headerInfoSB.append(BOUNDARY);
                    // \n 是换到下一行（的相同位置），\r 是回到行首
                    // 因此实际上，在 windows 中的回车键（敲一次 enter）就是 \r\n
                    headerInfoSB.append("\r\n");
                    headerInfoSB.append("Content-Disposition: form-data; name=\"" + fileKey + "\"; filename=\"" + fileName + "\"");
                    headerInfoSB.append("\r\n");
                    headerInfoSB.append("Content-Type: " + fileType);
                    headerInfoSB.append("\r\n");
                    headerInfoSB.append("\r\n");
                    byte[] headerInfoBytes = headerInfoSB.toString().getBytes(StandardCharsets.UTF_8);
                    outputStream.write(headerInfoBytes);
                      Log.d(TAG, "headerInfoSb === " + headerInfoSB.toString());
                    
                    // 文件内容
                    // 文件输入流是以字节的方式读取文件内容（数据），文件输出流是将数据写入到文件中
                    FileInputStream fileInputStream = new FileInputStream(file);
                    // 字节缓冲流、是高级的流，需要套在底层的流上以增加读写效率和其他方法
                    bufferedInputStream = new BufferedInputStream(fileInputStream);
                    byte[] buffer = new byte[1024];
                    int readLength;
                    while ((readLength = bufferedInputStream.read(buffer, 0, buffer.length)) != -1) {
                        outputStream.write(buffer, 0, readLength);
                    }
                    
                    // 主体的结尾部分
                    StringBuilder endingInfoSb = new StringBuilder();
                    endingInfoSb.append("\r\n");
                    endingInfoSb.append("--");
                    endingInfoSb.append(BOUNDARY);
                    endingInfoSb.append("--");
                    endingInfoSb.append("\r\n");
                    outputStream.write(endingInfoSb.toString().getBytes(StandardCharsets.UTF_8));
                    outputStream.flush();
                    
                    // 获取返回的结果
                    int responseCode = httpURLConnection.getResponseCode();
                    Log.d(TAG, "responseCode === " + responseCode);
                    if (responseCode == HttpURLConnection.HTTP_OK) {
                        inputStream = httpURLConnection.getInputStream();
                        // InputStreamReader 是字节流和字符流之间的桥梁。它读取字节，并使用指定的字符集将其解码为字符。
                        bufferedReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
                        String result = bufferedReader.readLine();
                        Log.d(TAG, "result is " + result);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (bufferedInputStream != null) {
                        try {
                            // 关闭包装流后，被包装的底层流也会自动关闭
                            bufferedInputStream.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (outputStream != null) {
                        try {
                            outputStream.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (bufferedReader != null) {
                        try {
                            bufferedReader.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    if (inputStream != null) {
                        try {
                            inputStream.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }).start();
    }
    ```
    
5. 权限申请（因为用到了获取存储卡的内容）：

    ```java
    // 这里的权限也可以用 Manifest.permission.READ_EXTERNAL_STORAGE 和 Manifest.permission.WRITE_EXTERNAL_STORAGE
    private static String[] PERMISSIONS_STORAGE = {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
    };
    public static final int PERMISSION_CODE = 1;
    
    /**
     * 动态获取 SD 卡权限
     */
    private void verifyStoragePermissions() {
        // 获取当前的权限情况（有还是无）
        int permission = ActivityCompat.checkSelfPermission(this,
                PERMISSIONS_STORAGE[1]);
        if ((permission != PackageManager.PERMISSION_GRANTED)) {
            // 没有写的权限，需要申请，此时弹出对话框
            //
            ActivityCompat.requestPermissions(this, PERMISSIONS_STORAGE, PERMISSION_CODE);
        }
    }
    
    // TODO: 还需要重写 onRequestPermissionsResult() 来对权限情况进行处理
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull @NotNull String[] permissions, @NonNull @NotNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
    ```



### 7. 多文件上传

1. 根据单文件上传的逻辑，可以将部分代码抽离重构：

    1. http 连接的建立抽离出一个方法，然后传入 `boundary` 的值就行。
    2. 上传的多个文件也可以抽离出一个方法，然后返回一个 `List<File>` 。
    3. 多文件上传的 http 请求的主体内容（根据实际情况）是头 + 主体 + 头 + 主体 + ... + 头 + 主体 + 结尾。
    4. 头、主体、结尾都可以抽离出方法出来。

2. 主体与主体之间的连接：

    ![image-20220213114817692](image-20220213114817692.png)

3. 请求样例

    ![image-20220213114922965](image-20220213114922965.png)

4. 代码：

    ```java
    public void postFiles(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String BOUNDARY = "--------------------------448401221482175638146520";
                OutputStream outputStream = null;
                try {
                    // 建立连接
                    HttpURLConnection httpURLConnection = getHttpURLConnection(BOUNDARY);
                    httpURLConnection.connect();
                    Log.d(TAG, "connection established");
                    
                    // 获取输出流
                    outputStream = httpURLConnection.getOutputStream();
                    
                    // 获取 Files
                    List<File> fileList = initFiles();
                    Iterator<File> fileIterator = fileList.iterator();
                    // 用迭代器迭代文件列表
                    while (fileIterator.hasNext()) {
                        File file = fileIterator.next();
                        // 获取主体头字符串
                        String bodyHeaderString = getBodyHeaderString(file, BOUNDARY);
                        outputStream.write(bodyHeaderString.getBytes(StandardCharsets.UTF_8));
                        
                          //// 文件内容
                          //// 文件输入流是以字节的方式读取文件内容（数据），文件输出流是将数据写入到文件中
                          //FileInputStream fileInputStream = new FileInputStream(file);
                          //// 字节缓冲流、是高级的流，需要套在底层的流上以增加读写效率和其他方法
                          //bufferedInputStream = new BufferedInputStream(fileInputStream);
                          //byte[] buffer = new byte[1024];
                          //int readLength;
                          //while ((readLength = bufferedInputStream.read(buffer, 0, buffer.length)) != -1) {
                          //    outputStream.write(buffer, 0, readLength);
                          //}
                          //// 主体结束后再补个换行，这样子下一个文件的头就可以接上
                          //outputStream.write("\r\n".getBytes(), 0, "\r\n".getBytes().length);
                          //bufferedInputStream.close();
                        
                        // 获取文件主体部分的文件输出流，即将上面注释内容的方法重构
                        outputStream = getBodyContentStream(outputStream, file);
                        
                        // 结尾，如果是最后一个文件，就要加
                        if (!fileIterator.hasNext()) {
                            String bodyEndingString = getBodyEndingString(BOUNDARY);
                            outputStream.write(bodyEndingString.getBytes(StandardCharsets.UTF_8));
                        }
                    }
                    outputStream.flush();
                    // 获取连接的返回内容
                    String result = getResponseContent(httpURLConnection);
                    if (result != null) {
                        Log.d(TAG, "result == " + result);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    if (outputStream != null) {
                        try {
                            outputStream.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }).start();
    }
    
    public List<File> initFiles() {
        List<File> fileList = new ArrayList<>();
        File file1 = new File("/storage/emulated/0/Download/904413721286148096.png");
        fileList.add(file1);
        File file2 = new File("/storage/emulated/0/Download/936603765992062976.jpg");
        fileList.add(file2);
        return fileList;
    }
    
    /**
     * 获取到 HttpURLConnection (多文件上传）
     *
     * @param BOUNDARY 由网页自动计算，也可以通过抓包获取一个
     * @return HttpURLConnection 返回一个 HttpURLConnection 的实例对象
     * @throws IOException
     */
    @NotNull
    private HttpURLConnection getHttpURLConnection(String BOUNDARY) throws IOException {
        URL url = new URL(BASE_URL + "/files/upload");
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setRequestMethod("POST");
        httpURLConnection.setConnectTimeout(10000);
        httpURLConnection.setRequestProperty("User-Agent", "Android/" + Build.VERSION.SDK_INT);
        httpURLConnection.setRequestProperty("Accept", "*/*");
        // 等同于 httpURLConnection.setUseCaches(false);
        httpURLConnection.setRequestProperty("Cache-Control", "no-cache");
        httpURLConnection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + BOUNDARY);
        httpURLConnection.setRequestProperty("Connection", "keep-alive");
        // 默认为 true
        httpURLConnection.setDoInput(true);
        // 默认为 false，因此需要开启
        httpURLConnection.setDoOutput(true);
        return httpURLConnection;
    }
    
    /**
     * 获取主体的头部部分
     *
     * @param file
     * @param BOUNDARY
     * @return
     */
    public String getBodyHeaderString(@NotNull File file, String BOUNDARY) {
        StringBuilder headerInfoSb = new StringBuilder();
        String fileKey = "files";
        String fileName = file.getName();
        String fileType = null;
        try {
            fileType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(MimeTypeMap.getFileExtensionFromUrl(file.toURI().toURL().toString()));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        // 准备发送数据的头部数据（是 http 中主体部分的）
        headerInfoSb.append("--");
        headerInfoSb.append(BOUNDARY);
        // \n 是换到下一行（的相同位置），\r 是回到行首
        // 因此实际上，在 windows 中的回车键（敲一次 enter）就是 \r\n
        headerInfoSb.append("\r\n");
        headerInfoSb.append("Content-Disposition: form-data; name=\"" + fileKey + "\"; filename=\"" + fileName + "\"");
        headerInfoSb.append("\r\n");
        headerInfoSb.append("Content-Type: " + fileType);
        headerInfoSb.append("\r\n");
        headerInfoSb.append("\r\n");
        Log.d(TAG, "stringBuilder.toString() === " + headerInfoSb.toString());
        return headerInfoSb.toString();
    }
    
    /**
     * 获得将文件转换成字节，输入到指定输出流的方法。
     *
     * @param httpURLConnectionOutputStream 从 httpURLConnection 获得的输出流
     * @param file 文件
     * @return 返回写入了文件的输出流
     */
    public OutputStream getBodyContentStream(OutputStream httpURLConnectionOutputStream, File file) {
        OutputStream outputStream = httpURLConnectionOutputStream;
        BufferedInputStream bufferedInputStream = null;
        try {
            // 文件内容
            // 文件输入流是以字节的方式读取文件内容（数据），文件输出流是将数据写入到文件中
            FileInputStream fileInputStream = new FileInputStream(file);
            // 字节缓冲流、是高级的流，需要套在底层的流上以增加读写效率和其他方法
            bufferedInputStream = new BufferedInputStream(fileInputStream);
            byte[] buffer = new byte[1024];
            int readLength;
            while ((readLength = bufferedInputStream.read(buffer, 0, buffer.length)) != -1) {
                outputStream.write(buffer, 0, readLength);
            }
            // 主体结束后再补个换行，这样子下一个文件的头就可以接上
            outputStream.write("\r\n".getBytes(), 0, "\r\n".getBytes().length);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return outputStream;
    }
    
    /**
     * 获取主体的结尾部分
     *
     * @param BOUNDARY
     * @return
     */
    public String getBodyEndingString(String BOUNDARY) {
        // 主体的结尾部分
        StringBuilder endingInfoSb = new StringBuilder();
        endingInfoSb.append("--");
        endingInfoSb.append(BOUNDARY);
        endingInfoSb.append("--");
        endingInfoSb.append("\r\n");
        return endingInfoSb.toString();
    }
    
    /**
     * 获取连接的返回结果
     *
     * @param httpURLConnection
     * @return result 返回的结果
     */
    public String getResponseContent(HttpURLConnection httpURLConnection) {
        String result = null;
        InputStream inputStream = null;
        BufferedReader bufferedReader = null;
        try {
            int responseCode = httpURLConnection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                inputStream = httpURLConnection.getInputStream();
                bufferedReader = new BufferedReader(
                        new InputStreamReader(inputStream, StandardCharsets.UTF_8));
                result = bufferedReader.readLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return result;
    }
    ```



### 8. 文件下载

1. 请求样例：

    ![image-20220213162444189](image-20220213162444189.png)

2. 处理思路：

    1. 发起 http 请求，获取返回码
    2. 获取返回包的 http 头部中的文件名
    3. 获取 app 下存放文件的路径以及创建新的文件
    4. 将获取到的数据通过流写入到新的文件中

3. 代码：

    ```java
        public void downloadFile(View view) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    Random random = new Random();
                    int randomNumber = random.nextInt(17);
                    BufferedOutputStream bufferedOutputStream = null;
                    BufferedInputStream bufferedInputStream = null;
                    // 判断文件的绝对路径是否已经创建
                    boolean isDirMked = false;
                    // 判断文件是否已经在目录中创建
                    boolean IsNewFileCreated = false;
                    try {
                        URL url = new URL(BASE_URL + "/download/" + randomNumber);
                        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                        httpURLConnection.setConnectTimeout(10000);
                        httpURLConnection.setRequestProperty("Accept", "*/*");
                        httpURLConnection.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9");
                        httpURLConnection.setRequestMethod("GET");
                        httpURLConnection.connect();
    
                        // 获取返回码以及返回包的 http 头内容
                        int responseCode = httpURLConnection.getResponseCode();
                        Log.d(TAG, "responseCode === " + responseCode);
                        if (responseCode == HttpURLConnection.HTTP_OK) {
                            Map<String, List<String>> headerFields = httpURLConnection.getHeaderFields();
                            for (Map.Entry<String, List<String>> stringListEntry : headerFields.entrySet()) {
                                Log.d(TAG, stringListEntry.getKey() + " = " + stringListEntry.getValue());
                            }
    
    //                        // 拿到 Content-disposition 的值（以列表的形式）
    //                        // 从结果来看，结果的列表就一个值。
    //                        List<String> strings = headerFields.get("Content-disposition");
    //                        for (String string : strings) {
    //                            Log.d(TAG, "string === " + string);
    //                        }
                            // 或者用这个方法返回值（以字符串的形式
                            String headerField = httpURLConnection.getHeaderField("Content-disposition");
                            Log.d(TAG, "headerField === " + headerField);
    
                            // 处理的方式一定要根据后台
                            // 字符串处理
                            int index = headerField.indexOf("filename=");
                            // 从 "=" 号向后切割
    //                        String filename = headerField.substring(index + "filename=".length());
    //                        Log.d(TAG, "filename === " + filename);
                            // 或者这样处理，将原来字符串的前面所有内容都变成空字符串
                            String filename = headerField.replace("attachment; filename=", "");
                            Log.d(TAG, "filename === " + filename);
    
                            // 这个方法在 api 29 时已经过时，根据提示，使用 Context 下面的 getExternalFilesDir()
    //                        Environment.getExternalStorageDirectory()
                            File picFileDir = RequestTestActivity.this.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
                            // 返回的结果如下：
                            // /storage/emulated/0/Android/data/com.example.androidnetworkdemo/files/Pictures
                            Log.d(TAG, "externalFilesDir is " + picFileDir.toString());
                            // 如果路径不存在，就创建绝对路径（因为获得的时候也是绝对路径
                            if (!picFileDir.exists()) {
                                isDirMked = picFileDir.mkdirs();
                            }
                            if (isDirMked) {
                                Log.d(TAG, "absolute dir was created");
                            }
                            // File.separator 是当前操作系统的文件路径分割符（即 "/" 或者 "\\"）
                            File file = new File(picFileDir + File.separator + filename);
                            // 如果文件不存在（也应该不存在），那就创建文件
                            if (file.exists()) {
                                IsNewFileCreated = file.createNewFile();
                            }
                            if (IsNewFileCreated) {
                                Log.d(TAG, "file was created");
                            }
                            FileOutputStream fileOutputStream = new FileOutputStream(file);
                            bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
                            InputStream httpURLConnectionInputStream = httpURLConnection.getInputStream();
                            bufferedInputStream = new BufferedInputStream(httpURLConnectionInputStream);
                            byte[] buffer = new byte[1024];
                            int length;
                            while ((length = bufferedInputStream.read(buffer, 0, buffer.length)) != -1) {
                                bufferedOutputStream.write(buffer, 0, length);
                            }
                            bufferedOutputStream.flush();
    
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        if (bufferedInputStream != null) {
    //                        try {
    //                            bufferedInputStream.close();
    //                        } catch (IOException e) {
    //                            e.printStackTrace();
    //                        }
                            // 使用自己创建的工具类：
                            IOUtils.ioClose(bufferedInputStream);
                        }
                        if (bufferedOutputStream != null) {
    //                        try {
    //                            bufferedOutputStream.close();
    //                        } catch (IOException e) {
    //                            e.printStackTrace();
    //                        }
                            // 使用自己创建的工具类：
                            IOUtils.ioClose(bufferedOutputStream);
                        }
                    }
    
                }
            }).start();
        }
    ```

4. IOUtils.java：

    ```java
    package com.example.androidnetworkdemo.Utils;
    
    import org.jetbrains.annotations.NotNull;
    
    import java.io.Closeable;
    import java.io.IOException;
    
    public class IOUtils {
    
        // 输入输出流均继承自 Closeable，因此调用他们父类的 close() 即可，就不用分输入流和输出流。
        public static void ioClose(@NotNull Closeable closeable) {
            try {
                closeable.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    ```



## 3. OkHttp 框架

### 1. 使用 OkHttp 发起 get 请求

#### 1. 过程

1. 首先要添加 OkHttp 的依赖：

    ```java
    implementation("com.squareup.okhttp3:okhttp:4.9.3")
    ```

2. 写一个客户端（OkHttpClient）（也就是 Call 的工厂）
3. 创建请求内容（Request 类），用来完善请求的一些信息
4. 用客户端创建请求任务（也就是 Call 类）（Call 类代表一个请求已经准备就绪，并且其也是用来发起 http 请求的类）
5. 执行同步或者异步请求
6. 通过 Response 类来获取返回码与返回的主体内容



#### 2. 代码

1. 发起请求的函数：

    ```java
    public void getRequestWithOkHttp(View view) {
        // 要现有一个客户端（浏览器）（也就是 Call 的工厂）
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(10000, TimeUnit.MILLISECONDS)
                .build();
        
        // 创建请求内容，用来完善请求的一些信息
        Request request = new Request
                .Builder()
                .get()
                .url(BASE_URL + "/get/text")
                .build();
        
        // 用 client 去创建请求任务，Call 代表一个请求已经准备被执行（类似一个任务已经准备就绪）
        Call task = okHttpClient.newCall(request);
        
        // 异步请求，enqueue 表示排队准备处理
        task.enqueue(new Callback() {
            /**
             * 请求失败时执行
             * @param call 请求任务
             * @param e 报错信息
             */
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                Log.d(TAG, "onFailure --> " + e.toString());
            }
            
            /**
             * 请求成功时执行
             * @param call
             * @param response
             * @throws IOException
             */
            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                // 获得响应码
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                
                if (code == HttpURLConnection.HTTP_OK) {
                    // 获取回包的主体内容，ResponseBody 继承自 Closeable，因此是一个流
                    ResponseBody body = response.body();
                    // ResponseBody.string() 方法表示将回包的主体部分以字符串的形式返回
                    if (body != null) {
                        Log.d(TAG, "body --> " + body.string());
                    }
                }
            }
        });
    }
    ```



#### 3. 结果

1. 获取的结果如下：![image-20220215003757371](image-20220215003757371.png)



### 2. 使用 OkHttp 通过 Post 方式提交评论

#### 1. 过程

1. 服务器接口图：

    ![image-20220215004001654](image-20220215004001654.png)

2. 由 1 可知，要发送的主体内容是一个 json 格式。那么考虑将样式的 json 通过 GsomFormatPlus 生成 JavaBean 类，然后把要评论的文章 id 和评论内容放到一个实例化的 JavaBean 类里面，然后再通过 Gson 的方法将其转换成 json 格式，放到发送包的主体即可。
3. 剩下步骤和使用 OkHttp 发起 get 请求一样。



#### 2. 代码

1. 发起请求的函数：

    ```java
    public void postComment(View view) {
        // 先有 client
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(10000, TimeUnit.MILLISECONDS)
                .build();
        
        // 获取 json（来自 JavaBean，然后这部分可以封装，从 UI 获取评论的内容
        CommentItem commentItem = new CommentItem("123456789", "我是评论的内容");
        Gson gson = new Gson();
        String jsonStr = gson.toJson(commentItem);
        // 设置 MIME
        MediaType mediaType = MediaType.get("application/json; charset=utf-8");
        // 这里 create() 的第一个参数是请求的主体部分的字符串形式，
        RequestBody requestBody = RequestBody.create(jsonStr, mediaType);
        
        // 创建请求内容，用来完善请求的一些信息
        Request request = new Request
                .Builder()
                .post(requestBody)
                .url(BASE_URL + "/post/comment")
                .build();
        
        Call call = okHttpClient.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                Log.d(TAG, "onFailure --> " + e.toString());
            }
            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                int code = response.code();
                Log.d(TAG, "code === " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    ResponseBody body = response.body();
                    if (body != null) {
                        Log.d(TAG, "result --> " + body.string());
                    }
                }
            }
        });
    }
    ```

    

#### 3. 结果

1. 成功返回的结果如下：

    ![image-20220215004728392](image-20220215004728392.png)



### 3. OkHttp 为 get 请求添加参数

1. 创建 HttpUrl.Builder 的实例
2. 然后该实例中调用 `addQueryParameter(String key, String value)` 来添加参数
3. 在 request 中，`.url(实例.build())`
4. 参考 [OKHttp3带参数发送get和post请求工具类_qq243920161的博客-CSDN博客_okhttp3发送get请求](https://blog.csdn.net/qq243920161/article/details/103589593)



### 4. 通过 OkHttp 进行单文件上传

#### 1. 过程

1. 创建 client

2. 创建 File 对象，获取该文件的 MIME 类型

3. 在 Request 对象中，`.post()` 方法里面要传入 RequestBody，然后 MultipartBody.Builder 类里面可以通过 `.addFormDataPart()` 方法传入主体内容。接着 `.addFormDataPart()` 又需要一个 RequestBody 类，因此创建一个 Request 的实例，用 `create(File file, MediaType contentType)` 来创建。

4. 第 3 点往回创建响应的东西即可

5. 创建 Call

6. 异步请求

7. 接口定义：

    ![image-20220215115532636](image-20220215115532636.png)



#### 2. 代码

1. 实现代码：

    ```java
    public void postFile(View view) throws MalformedURLException {
        // 先有 client
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(10000, TimeUnit.MILLISECONDS)
                .build();
        
        File file = new File("/storage/emulated/0/Download/904413721286148096.png");
        // 获取文件的 MIME 类型
        MediaType fileType = MediaType.get(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(file.toURI().toURL().toString())));
        RequestBody fileBody = RequestBody.create(file, fileType);
        // 根据 MultipartBody.Builder().addFormDataPart() 里面的参数要求，逐个创建参数
        // MultipartBody 对应的就是 http 中的 Multipart 字段
        RequestBody requestBody = new MultipartBody.Builder()
                .addFormDataPart("file", file.getName(), fileBody).build();
        Request request = new Request.Builder()
                .url(BASE_URL + "/file/upload")
                .post(requestBody)
                .build();
        
        // 创建 call
        Call task = okHttpClient.newCall(request);
        // 异步请求
        task.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                Log.d(TAG, "onFailure ..." + e.toString());
            }
            
            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                int code = response.code();
                Log.d(TAG, "code === " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    ResponseBody body = response.body();
                    if (body != null) {
                        String string = body.string();
                        Log.d(TAG, "result --> " + string);
                    }
                }
            }
        });
    }
    ```



#### 3. 结果

1. 上传结果：![image-20220215114312635](image-20220215114312635.png)



### 5. 通过 OkHttp 上传多个文件

#### 1. 过程

1. 由上面可知，只需要创建多个 File，多创建 requestBody 和 调用 `addFormDataPart()` 即可。

2. 在 OkHttp 的 Receipes 中，其给出了上传单个文件的其他方法：

    ```java
     public static final MediaType MEDIA_TYPE_MARKDOWN
          = MediaType.parse("text/x-markdown; charset=utf-8");
    
      private final OkHttpClient client = new OkHttpClient();
    
      public void run() throws Exception {
        File file = new File("README.md");
    
        Request request = new Request.Builder()
            .url("https://api.github.com/markdown/raw")
            .post(RequestBody.create(MEDIA_TYPE_MARKDOWN, file))
            .build();
    
        try (Response response = client.newCall(request).execute()) {
          if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);
    
          System.out.println(response.body().string());
        }
      }
    ```

    即直接传入一个 RequestBody 即可（和提交评论一样，本质上就是 post 传一个主体）

3. 通过 MultipartBody 来上传文件，可以上传多个文件。

4. 接口定义：

    ![image-20220215115508226](image-20220215115508226.png)



#### 2. 代码

1. 执行函数：

    ```java
    public void postFiles(View view) throws MalformedURLException {
        // 先有 client
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(10000, TimeUnit.MILLISECONDS)
                .build();
        
        File fileOne = new File("/storage/emulated/0/Download/904413721286148096.png");
        File fileTwo = new File("/storage/emulated/0/Download/936603765992062976.jpg");
        
        // 获取文件的 MIME 类型
        MediaType fileOneType = MediaType.get(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(fileOne.toURI().toURL().toString())));
        MediaType fileTwoType = MediaType.get(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(fileOne.toURI().toURL().toString())));
        RequestBody fileOneBody = RequestBody.create(fileOne, fileOneType);
        RequestBody fileTwoBody = RequestBody.create(fileTwo, fileTwoType);
        // 根据 MultipartBody.Builder().addFormDataPart() 里面的参数要求，逐个创建参数
        // MultipartBody 对应的就是 http 中的 Multipart 字段
        // 这里 post 传输的 requestBody 相当于嵌套了多个 requestBody
        RequestBody requestBody = new MultipartBody.Builder()
                .addFormDataPart("files", fileOne.getName(), fileOneBody)
                .addFormDataPart("files", fileTwo.getName(), fileTwoBody)
                .build();
        Request request = new Request.Builder()
                .url(BASE_URL + "/files/upload")
                .post(requestBody)
                .build();
        
        // 创建 call
        Call task = okHttpClient.newCall(request);
        // 异步请求
        task.enqueue(new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                Log.d(TAG, "onFailure ..." + e.toString());
            }
            
            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                int code = response.code();
                Log.d(TAG, "code === " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    ResponseBody body = response.body();
                    if (body != null) {
                        String string = body.string();
                        Log.d(TAG, "result --> " + string);
                    }
                }
            }
        });
    }
    ```



#### 3. 结果

1. 结果：

    ![image-20220215115417382](image-20220215115417382.png)



### 6. 通过 OkHttp 下载文件

#### 1. 过程

1. 接口：

    ![image-20220215135417437](image-20220215135417437.png)

2. 正常发起请求

3. 主要的逻辑处理在返回包上。

4. 首先要拿到返回包的头部，截取出文件的名字

5. 接着创建一个 File 等待写入。

6. 判断文件所在的目录是否创建，没有则需要创建文件夹

7. 判断第 4 点的文件是否存在，不存在就创建

8. 获取返回包的输入流并创建文件的输出流。

9. 字节读取并输入。



#### 2. 代码

```java
public void downloadFile(View view) {
    // 先有 client
    OkHttpClient okHttpClient = new OkHttpClient.Builder()
            .connectTimeout(10000, TimeUnit.MILLISECONDS)
            .build();
    
    // 用一个随机数来获取不同的图片
    Random random = new Random();
    
    // 构造请求内容
    Request request = new Request.Builder()
            .get()
            .url(BASE_URL + "/download/" + random.nextInt(17))
            .build();
    
    // 获取任务（call）
    final Call call = okHttpClient.newCall(request);
    // 同步执行，需要异常处理，因此可以在子进程中进行
    new Thread(new Runnable() {
        @Override
        public void run() {
            BufferedInputStream bufferedInputStream = null;
            BufferedOutputStream bufferedOutputStream = null;
            try {
                Response execute = call.execute();
                int code = execute.code();
                // 如果返回码是 200
                if (code == HttpURLConnection.HTTP_OK) {
                    Headers headers = execute.headers();
                    // 遍历拿到返回包的头部
                    for (int i = 0; i < headers.size(); i++) {
                        String key = headers.name(i);
                        String value = headers.value(i);
                        Log.d(TAG, key + " === " + value);
                    }
                    
                    // 拿到下载的文件名
                    String fileName = headers.get("Content-disposition").
                            replace("attachment; filename=", "");
                    // 创建文件，加分割符的还有一个目的就是将参数的第一个部分从 file 转换成 String
                    File outFile = new File(OkHttpActivity.this.getExternalFilesDir(Environment.DIRECTORY_PICTURES) + File.separator + fileName);
                    // 如果这个文件所在的上一级目录不存在的话（也就是没有文件夹），那么就一直创建文件夹直到上级
                    if (!Objects.requireNonNull(outFile.getParentFile()).exists()) {
                        outFile.mkdirs();
                    }
                    // 如果文件不存在，就创建文件
                    if (!outFile.exists()) {
                        outFile.createNewFile();
                    }
                    
                    if (execute.body() != null) {
                        // 获取输入流
                        InputStream inputStream = execute.body().byteStream();
                        bufferedInputStream = new BufferedInputStream(inputStream);
                        // 创建文件输出流
                        bufferedOutputStream = new BufferedOutputStream(
                                new FileOutputStream(outFile));
                        byte[] buffer = new byte[1024];
                        int length;
                        // 文件字节写入
                        while ((length = bufferedInputStream.read(buffer, 0, buffer.length)) != -1) {
                            bufferedOutputStream.write(buffer, 0, length);
                        }
                        bufferedOutputStream.flush();
                    }
                    
                    if (outFile.exists()) {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                Toast.makeText(OkHttpActivity.this, "下载 " + fileName + " 成功", Toast.LENGTH_LONG).show();
                            }
                        });
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (bufferedInputStream != null) {
                    IOUtils.ioClose(bufferedInputStream);
                }
                if (bufferedOutputStream != null) {
                    IOUtils.ioClose(bufferedOutputStream);
                }
            }
        }
    }).start();
}
```



#### 3. 结果

1. 返回的结果：

    ![image-20220215135716256](image-20220215135716256.png)



### 7.  OkHttp 

1. 官网：[Overview - OkHttp (square.github.io)](https://square.github.io/okhttp/)
2. 一些常见的运用方法可以查看官网中的 Recipes：[Recipes - OkHttp (square.github.io)](https://square.github.io/okhttp/recipes/)



## 4. retrofit 框架封装

### 1. 使用 retrofit 发起 get 请求并将数据在 UI 上显示

#### 1. 过程

1. 新建一个接口，叫 Api.java。
2. 然后创建 Get 注释，里面的参数为相对路径，表示请求的方式是 Get
3. 创建一个方法，返回值为 `Call<ResponseBody>` 。
4. 在发起请求的方法中，先实例化一个 Retrofit 对象，实例化的过程中，需要调用 `.baseUrl(BASE_URL)` 来指明基本的 Url。
5. 用 Retrofit 对象创建接口实例，实现接口。
6. 调用第 3 点创建的方法，拿到一个 Call 以发起 http 请求
7. 接下来和用 OkHttp 发起请求一样。
8. 用 RecyclerView 显示获取的 Json 数据



#### 2. 代码

1. MainActivity.java：

    ```java
    package com.example.retrofitdemo;
    
    import androidx.appcompat.app.AppCompatActivity;
    import androidx.recyclerview.widget.LinearLayoutManager;
    import androidx.recyclerview.widget.ListAdapter;
    import androidx.recyclerview.widget.RecyclerView;
    
    import android.os.Bundle;
    import android.util.Log;
    import android.view.View;
    
    import com.example.retrofitdemo.adapters.ListViewAdapter;
    import com.example.retrofitdemo.domain.JsonResult;
    import com.example.retrofitdemo.interfaces.Api;
    import com.google.gson.Gson;
    
    import java.io.IOException;
    import java.net.HttpURLConnection;
    
    import okhttp3.ResponseBody;
    import retrofit2.Call;
    import retrofit2.Callback;
    import retrofit2.Response;
    import retrofit2.Retrofit;
    
    public class MainActivity extends AppCompatActivity {
    
        private static final String TAG = "MainActivity";
        private RecyclerView mResultList;
        private ListViewAdapter mListViewAdapter;
    
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            initView();
        }
    
        private void initView() {
            mResultList = this.findViewById(R.id.result_list);
            mResultList.setLayoutManager(new LinearLayoutManager(this));
            mListViewAdapter = new ListViewAdapter();
            mResultList.setAdapter(mListViewAdapter);
        }
    
        public void getRequest(View view) {
            // Retrofit 的本质作用是将对 http 的 api 抽成一个 java 接口
            // 相当于将 OkHttp 中设置 url，设置 multipart 等一系列操作再抽成接口
            // 这里个人认为类似创建 client，但是比 client 更简洁，而且还设置了 baseUrl
            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl("http://192.168.43.110:9102")
                    .build();
    
            // 创建接口实例，实现接口
            Api api = retrofit.create(Api.class);
            // 准备执行 http 请求，至于这个请求的 request（也就是具体的请求头内容或者其他内容的设置）取决于其在接口中的定义
            // 这里的 getJson() 在接口中的参数什么也没有指明，因此这里就是单纯的发出一个 http 请求
            Call<ResponseBody> task = api.getJson();
            // 异步发起 http 请求
            task.enqueue(new Callback<ResponseBody>() {
                @Override
                public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {
                    String result;
                    int code = response.code();
                    Log.d(TAG, "code --> " + code);
                    if (code == HttpURLConnection.HTTP_OK) {
                        try {
                            result = response.body().string();
    //                        Log.d(TAG, "json --> " + result);
    
                            Gson gson = new Gson();
                            JsonResult jsonResult = gson.fromJson(result, JsonResult.class);
                            updateList(jsonResult);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
    
                private void updateList(JsonResult jsonResult) {
                    mListViewAdapter.setData(jsonResult);
                }
    
                @Override
                public void onFailure(Call<ResponseBody> call, Throwable t) {
                    Log.d(TAG, "onFailure " + t.toString());
                }
            });
        }
    }
    ```

2. ListViewAdapter.java

    ```java
    package com.example.retrofitdemo.adapters;
    
    import android.view.LayoutInflater;
    import android.view.View;
    import android.view.ViewGroup;
    import android.widget.ImageView;
    import android.widget.TextView;
    
    import androidx.annotation.NonNull;
    import androidx.recyclerview.widget.RecyclerView;
    
    import com.bumptech.glide.Glide;
    import com.example.retrofitdemo.R;
    import com.example.retrofitdemo.domain.JsonResult;
    
    import org.jetbrains.annotations.NotNull;
    
    import java.util.ArrayList;
    import java.util.List;
    
    public class ListViewAdapter extends RecyclerView.Adapter<ListViewAdapter.InnerHolder> {
    
        private List<JsonResult.DataBean> mDataBeanList = new ArrayList<>();
    
        @NonNull
        @NotNull
        @Override
        public InnerHolder onCreateViewHolder(@NonNull @NotNull ViewGroup parent, int viewType) {
            // 渲染获得 item 的 view
            View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_json_result, null);
            return new InnerHolder(itemView);
        }
    
        @Override
        public void onBindViewHolder(@NonNull @NotNull InnerHolder holder, int position) {
            // 绑定数据
            // 获得当前位置的 JavaBean
            JsonResult.DataBean dataBean = mDataBeanList.get(position);
            // 传入的相当于是 data 中的一项
            holder.setItemData(dataBean);
        }
    
        @Override
        public int getItemCount() {
            return mDataBeanList.size();
        }
    
        public void setData(JsonResult jsonResult) {
            // 先把数据列表清除一遍
            mDataBeanList.clear();
            // 将 json 中键为 Data 的 JavaBean 写入
            mDataBeanList.addAll(jsonResult.getData());
            notifyDataSetChanged();
        }
    
    
        public class InnerHolder extends RecyclerView.ViewHolder {
    
            private final ImageView mResultIcon;
            private final TextView mResultTitle;
            private final TextView mResultUserName;
            private final TextView mResultViewCount;
            private final TextView mResultCommentCount;
    
            public InnerHolder(@NonNull @NotNull View itemView) {
                super(itemView);
                mResultIcon = itemView.findViewById(R.id.result_icon_item);
                mResultTitle = itemView.findViewById(R.id.result_title_item);
                mResultUserName = itemView.findViewById(R.id.result_username_item);
                mResultViewCount = itemView.findViewById(R.id.result_ViewCount_item);
                mResultCommentCount = itemView.findViewById(R.id.result_commentCount_item);
            }
    
            public void setItemData(JsonResult.DataBean dataBean){
                Glide.with(itemView.getContext())
                        .load("http://192.168.43.110:9102" + dataBean.getCover())
                        .into(mResultIcon);
                mResultTitle.setText(dataBean.getTitle());
                mResultUserName.setText(dataBean.getUserName());
                mResultViewCount.setText(dataBean.getViewCount() + "");
                mResultCommentCount.setText(dataBean.getCommentCount() + "");
    
            }
        }
    }
    ```

3. jsonResult.java 由返回获取到的 json 数据使用 GsonFormatPlus 生成。

4. activity_main.xml：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        xmlns:tools="http://schemas.android.com/tools"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical"
        tools:context=".MainActivity">
    
        <Button
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:onClick="getRequest"
            android:text="getRequest"
            android:textAllCaps="false" />
    
        <androidx.recyclerview.widget.RecyclerView
            android:id="@+id/result_list"
            android:layout_width="match_parent"
            android:layout_height="wrap_content">
    
        </androidx.recyclerview.widget.RecyclerView>
        
    </LinearLayout>
    ```

    ![image-20220215161045774](image-20220215161045774.png)

5. item_json_result.xml：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="horizontal">
    
        <androidx.cardview.widget.CardView
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:background="#fff000"
            app:cardBackgroundColor="#f6fDf0"
            app:cardCornerRadius="5dp"
            app:cardElevation="7dp"
            app:cardUseCompatPadding="true">
    
            <LinearLayout
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:orientation="horizontal" >
    
                <ImageView
                    android:id="@+id/result_icon_item"
                    android:layout_width="80dp"
                    android:layout_height="80dp"
                    android:scaleType="fitXY"
                    android:src="@mipmap/ic_launcher" />
    
                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:orientation="vertical">
    
                    <TextView
                        android:id="@+id/result_title_item"
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:layout_marginTop="10dp"
                        android:ellipsize="end"
                        android:lines="1"
                        android:text="我是标题"
                        android:layout_marginLeft="10dp"
                        android:textSize="30sp" />
    
                    <LinearLayout
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:layout_marginTop="15dp"
                        android:layout_marginLeft="10dp"
                        android:orientation="horizontal">
    
                        <TextView
                            android:id="@+id/result_username_item"
                            android:layout_width="wrap_content"
                            android:layout_height="wrap_content"
                            android:text="作者："
                            android:textSize="18sp" />
    
                        <TextView
                            android:id="@+id/result_ViewCount_item"
                            android:layout_width="wrap_content"
                            android:layout_height="wrap_content"
                            android:layout_marginLeft="50dp"
                            android:text="阅览数："
                            android:textSize="18sp" />
    
                        <TextView
                            android:id="@+id/result_commentCount_item"
                            android:layout_width="wrap_content"
                            android:layout_height="wrap_content"
                            android:layout_marginLeft="30dp"
                            android:text="评论数："
                            android:textSize="18sp" />
    
                    </LinearLayout>
    
                </LinearLayout>
    
            </LinearLayout>
    
        </androidx.cardview.widget.CardView>
    
    </LinearLayout>
    ```

    ![image-20220215161159695](image-20220215161159695.png)



#### 3. 结果

![image-20220215161531293](image-20220215161531293.png)



### 2. 使用转换器将接收的 json 数据转成对象

#### 1. 过程

1. 这里先将 Retrofit 的创建重构成一个工具类，这样每次直接调用即可。

2. 要将 json 转成对象，首先要添加一下依赖：

    ```java
    implementation 'com.squareup.retrofit2:converter-gson:2.9.0'
    ```

3. 然后在创建 Retrofit 对象时，调用 `addConverterFactory(GsonConverterFactory.create())` 来添加工厂。

4. 在接口中，原先的接收数据类 --- RequestBody 改成自己定义的 JavaBean 类。这样在获得返回结果（`response.body()`）就是自己定义的 JavaBean 类。



#### 2. 代码

1. 工具 RetrofitManager.java （接下来创建 Retrofit 对象的时候都会用到）

    ```java
    package com.example.retrofitdemo.Utils;
    
    import retrofit2.Retrofit;
    import retrofit2.converter.gson.GsonConverterFactory;
    
    public class RetrofitManager {
        // Retrofit 的本质作用是将对 http 的 api 抽成一个 java 接口
        // 相当于将 OkHttp 中设置 url，设置 multipart 等一系列操作再抽成接口
        // 这里个人认为类似创建 client，但是比 client 更简洁，而且还设置了 baseUrl
        private static Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("http://192.168.43.110:9102")
                .addConverterFactory(GsonConverterFactory.create())
                .build();
    
        public static Retrofit getRetrofit() {
            return retrofit;
        }
    }
    ```

2. 接口定义（在接口 Api.java 中）：

    ```java
    // Call<>，<> 中是接收数据的类
    @GET("/get/text")
    Call<JsonResult> getJson();
    ```

3. 逻辑方法（其他的详见上面大点 1）：

    ```java
    public void getRequest(View view) {
        // 创建接口实例，实现接口
        Api api = RetrofitManager.getRetrofit().create(Api.class);
        // 准备执行 http 请求，至于这个请求的 request（也就是具体的请求头内容或者其他内容的设置）取决于其在接口中的定义
        // 这里的 getJson() 在接口中的参数什么也没有指明，因此这里就是单纯的发出一个 http 请求
        Call<JsonResult> task = api.getJson();
        // 异步发起 http 请求
        task.enqueue(new Callback<JsonResult>() {
            @Override
            public void onResponse(@NotNull Call<JsonResult> call, @NotNull Response<JsonResult> response) {
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    // 将接口的接收返回结果的类改成 JsonResult 后，现在 response.body() 返回的类型就是 JsonResult
                    // 其自动将 json 转成了 JsonResult 类，前提是需要设置转换工厂和转换器
                    JsonResult result = response.body();
                    updateList(result);
                }
            }
            
            // 将获得到的 json 数据传入到 adapter 处理
            private void updateList(JsonResult jsonResult) {
                mListViewAdapter.setData(jsonResult);
            }
            
            @Override
            public void onFailure(Call<JsonResult> call, Throwable t) {
                Log.d(TAG, "onFailure " + t.toString());
            }
        });
    }
    ```



### 3. 使用 @Query 注解发起带参数的请求

#### 1. 过程

1. 在接口方法的参数中添加 `@Query("key") String key`，代表调用该方法时传入的值是键 "key" 的值，可以传入多个。



#### 2. 代码

1. 逻辑方法：

    ```java
    public void getWithParams(View view) {
        // 将前面实例化 Retrofit 的代码抽取成一个工具类
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        // 实例化 call，注意用 getWithParams() 方法
        Call<GetWithParamsResult> call = api.getWithParams("我是搜索的关键字...", "5", "0");
        call.enqueue(new Callback<GetWithParamsResult>() {
            @Override
            public void onResponse(@NotNull Call<GetWithParamsResult> call, @NotNull Response<GetWithParamsResult> response) {
                // 因为这里调用的是 .body() 的 toString()，因此 GetWithParamsResult 要重写 toString() 方法
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    // data 是个 JavaBean，如果不重写其 toString()，那么返回的内容为内存地址
                    Log.d(TAG, "Response --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<GetWithParamsResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```

2. 接口中定义的方法：

    ```java
    // 接收数据的类由返回的 json 使用工具生成
    // 用 @Query 来添加参数
    @GET("/get/param")
    Call<GetWithParamsResult> getWithParams(@Query("keyword") String keyword,
                                            @Query("page") String page,
                                            @Query("order") String order);
    ```

3. GetWithParamsResult 类由请求结果返回的 json 使用工具生成。



#### 3. 结果

1. 结果截图：

    ![image-20220218222805633](image-20220218222805633.png)



### 4. 使用 @QueryMap 注解来往 url 中传入多个参数

#### 1. 过程

1. 在接口方法的参数中添加 `@QueryMap Map<String, String> params` ，代表传入的 map 就是多个参数（键值对）。



#### 2. 代码

1. 接口方法定义：

    ```java
    // 重载方法，如果参数很多的时候，就传入一个 Map
    @GET("/get/param")
    Call<GetWithParamsResult> getWithParams(@QueryMap Map<String, Object> params);
    ```

2. 逻辑方法：

    ```java
    public void getWithParams_QueryMap(View view) {
        // 将前面实例化 Retrofit 的代码抽取成一个工具类
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        
        Map<String, Object> params = new HashMap<>();
        params.put("keyword", "我是通过 Map 的关键字");
        params.put("page", "5");
        params.put("order", "0");
        // 实例化 call，注意用 getWithParams() 方法
        Call<GetWithParamsResult> call = api.getWithParams(params);
        call.enqueue(new Callback<GetWithParamsResult>() {
            @Override
            public void onResponse(@NotNull Call<GetWithParamsResult> call, @NotNull Response<GetWithParamsResult> response) {
                // 因为这里调用的是 .body() 的 toString()，因此 GetWithParamsResult 要重写 toString() 方法
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    // data 是个 JavaBean，如果不重写其 toString()，那么返回的内容为内存地址
                    Log.d(TAG, "Response --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<GetWithParamsResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```



### 4. @Url 注释的使用

#### 1. 代码

1. 接口方法的定义：

    ```java
    // 不指明 url，让 url 传进来
    @POST
    Call<PostWithParamsResult> postWithUrl(@Url String url);
    ```

2. 逻辑方法（基本的 Url 在 retrofit 中已经定义）：

    ```java
    public void postWithUrl(View view) {
        // 将前面实例化 Retrofit 的代码抽取成一个工具类
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        
        String url = "/post/string?string=测试内容";
        Call<PostWithParamsResult> postWithParamsResultCall = api.postWithUrl(url);
        postWithParamsResultCall.enqueue(new Callback<PostWithParamsResult>() {
            @Override
            public void onResponse(Call<PostWithParamsResult> call, Response<PostWithParamsResult> response) {
                // 因为这里调用的是 .body() 的 toString()，因此 PostWithParamsResult 要重写 toString() 方法
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "Response --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<PostWithParamsResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```



#### 2. 结果

1. 结果截图：

    ![image-20220218223715980](image-20220218223715980.png)



### 5. 用 @Body 注解来上传 json 内容

#### 1. 过程

1. 由提交评论的主体内容可知，要提交一个 json 格式的数据来发表评论。
2. @Body 注解表示直接控制请求的主体内容。主体内容会用指定的 Converter 来序列化。



#### 2. 代码

1. 接口方法定义（PostWithParamsResult 和 PostCommentItem 类需要自己根据 json 来转换定义）：

    ```java
    // 用 post 提交评论（主体部分为 json）
    // 注意分辨接收数据的类和提交数据的类
    // @Body 注解表示直接控制请求的主体内容。主体内容会用指定的 Converter 来序列化。
    @POST("/post/comment")
    Call<PostWithParamsResult> postBody(@Body PostCommentItem commentItem);
    ```

2. 逻辑方法：

    ```java
    public void postWithBody(View view) {
        PostCommentItem postCommentItem = new PostCommentItem("123456", "点赞");
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        Call<PostWithParamsResult> postWithParamsResultCall = api.postBody(postCommentItem);
        postWithParamsResultCall.enqueue(new Callback<PostWithParamsResult>() {
            @Override
            public void onResponse(@NotNull Call<PostWithParamsResult> call, @NotNull Response<PostWithParamsResult> response) {
                int code = response.code();
                Log.d(TAG, "code === " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "responseBody --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<PostWithParamsResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```



#### 3. 结果

1. 结果截图：

    ![image-20220218225308040](image-20220218225308040.png)



### 6. 使用 @Part 和 @Multipart 注解来上传文件

#### 1. 过程

1. @Multipart 的 @Target 是 METHOD，因此它需要写在方法上面。
2. 一般 @Part 注释的对象是键的值（当然值也可以是自己的类，但需要 Conventor），或者是 MultipartBody.Part。
3. 在逻辑方法中创建 MultipartBody.Part 的对象，至于创建的方法（偏工厂模式的创建方法）和参数可以根据提示与要求。



#### 2. 代码

1. 接口方法定义：

    ```java
    // 使用 @Part 和 MultipartBody.Part 来上传图片
    @POST("/file/upload")
    @Multipart
    Call<PostFileResult> postFile(@Part MultipartBody.Part part);
    ```

2. 逻辑方法：

    ```java
    public void postFile(View view) throws MalformedURLException {
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        
        File file = new File("/storage/emulated/0/Download/904413721286148096.png");
        MediaType fileType = MediaType.parse(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(file.toURI().toURL().toString())));
        
        RequestBody requestBody = RequestBody.create(file, fileType);
        // 指定键值对和 MultipartBody 的主体内容
        // 偏工厂模式的创建方法
        MultipartBody.Part part = MultipartBody.Part.createFormData("file", file.getName(), requestBody);
        Call<PostFileResult> postFileResultCall = api.postFile(part);
        postFileResultCall.enqueue(new Callback<PostFileResult>() {
            @Override
            public void onResponse(Call<PostFileResult> call, Response<PostFileResult> response) {
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "response --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<PostFileResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```

3. 动态权限申请：

    ```java
    public class RequestActivity extends AppCompatActivity {
    
        private static final String TAG = "RequestActivity";
        private static String[] PERMISSIONS_STORAGE = {
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE"
        };
    
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_request);
    
            // 动态获取 SD 卡权限
            verifyStoragePermissions();
        }
    
        /**
         * 在 Android 8.0 以上的版本中，需要对一些权限使用动态获取
         */
        public void verifyStoragePermissions() {
            int permission = ActivityCompat.checkSelfPermission(RequestActivity.this,
                    PERMISSIONS_STORAGE[1]);
            if ((permission != PackageManager.PERMISSION_GRANTED)) {
                // 没有写的权限，需要申请，此时弹出对话框
                ActivityCompat.requestPermissions(RequestActivity.this, PERMISSIONS_STORAGE, 1);
            }
        }
    
        // 处理授予权限后的操作
        @Override
        public void onRequestPermissionsResult(int requestCode, @NonNull @NotNull String[] permissions, @NonNull @NotNull int[] grantResults) {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
            if (requestCode == 1) {
                // 如果同意授予权限
                // ...
            } else {
                this.finish();
            }
        }
    ```



#### 3. 结果

1. 返回结果截图：

    ![image-20220218231153979](image-20220218231153979.png)



### 7. 上传多个文件

#### 1. 过程

1. 上传多个文件就用这个方法，下文会讲一个不行的方法。



#### 2. 代码

1. 接口定义：

    ```java
    // 上传多个文件
    @POST("/files/upload")
    @Multipart
    Call<PostFileResult> postFiles(@Part List<MultipartBody.Part> parts);
    ```

2. 逻辑方法：

    ```java
    public void postFiles(View view) throws MalformedURLException {
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        // 创建列表
        List<MultipartBody.Part> parts = new ArrayList<>();
        
        File file1 = new File("/storage/emulated/0/Download/904413721286148096.png");
        File file2 = new File("/storage/emulated/0/Download/941345164977242112.png");
        MediaType fileType1 = MediaType.parse(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(file1.toURI().toURL().toString())));
        MediaType fileType2 = MediaType.parse(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(file2.toURI().toURL().toString())));
        
        RequestBody requestBody1 = RequestBody.create(file1, fileType1);
        RequestBody requestBody2 = RequestBody.create(file2, fileType2);
        
        MultipartBody.Part part1 = MultipartBody.Part.createFormData("files", file1.getName(), requestBody1);
        MultipartBody.Part part2 = MultipartBody.Part.createFormData("files", file2.getName(), requestBody2);
        
        parts.add(part1);
        parts.add(part2);
        
        Call<PostFileResult> postFileResultCall = api.postFiles(parts);
        postFileResultCall.enqueue(new Callback<PostFileResult>() {
            @Override
            public void onResponse(Call<PostFileResult> call, Response<PostFileResult> response) {
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "response --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<PostFileResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```



#### 3. 结果

1. 结果截图：

    ![image-20220218231848834](image-20220218231848834.png)



### 8. 文件上传并通过 POST 上传一些相关信息（例如注释）

#### 1. 过程

1. 详见接口定义的注解

2. 服务器接口方法：

    ![image-20220218232401747](image-20220218232401747.png)



#### 2. 代码

1. 接口方法的定义：

    ```java
    // 上传需要带有额外信息的文件
    // 这里的 @PartMap 可以用 Map<String, MultipartBody.Part> 来上传多个文件。
    // 可以看出，@Part("键") 或者 @PartMap Map<键, 值>。也就是说，有两种方式来增加。
    // 如果用 Map 和 @Part("键") 来指定，那么可以不用 MultipartBody.Part.createFormData
    // 其他的情况，例如 @Part 不加任何参数的话，就要调用 MultipartBody.Part.createFormData 来指定值
    
    // 需要注意的是，@PartMap Map 中的 value 不能为 MultipartBody.Part
    // 报错信息：@PartMap values cannot be MultipartBody.Part. Use @Part List<Part> or a different value type instead.
    // 因此用 @Part List<Part> parts 配合 MultipartBody.Part.createFormData 来进行多文件上传
    @POST("/file/params/upload")
    @Multipart
    Call<PostFileResult> postFileWithParams(@Part MultipartBody.Part part,
                                            @PartMap Map<String, String> params,
                                            @Part("isFree") String isFree);
    ```

2. 逻辑方法：

    ```java
    public void postFileWithParams(View view) throws MalformedURLException {
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        
        // 获得文件和文件的 MIME 类型
        File file = new File("/storage/emulated/0/Download/904413721286148096.png");
        MediaType fileType = MediaType.parse(MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(MimeTypeMap
                        .getFileExtensionFromUrl(file.toURI().toURL().toString())));
        
        RequestBody requestBody = RequestBody.create(file, fileType);
        MultipartBody.Part part = MultipartBody.Part.createFormData("file", file.getName(), requestBody);
        Map<String, String> params = new HashMap<>();
        
        // 这里可以看出：添加参数有两种办法，一种就是传入 @PartMap，另外一种就是 @Part("键") 值的类型 值
        params.put("description", "这是一张图片");
        
        Call<PostFileResult> postFileResultCall = api.postFileWithParams(part, params, "false");
        postFileResultCall.enqueue(new Callback<PostFileResult>() {
            @Override
            public void onResponse(Call<PostFileResult> call, Response<PostFileResult> response) {
                int code = response.code();
                Log.d(TAG, "code --> " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "response --> " + response.body().toString());
                }
            }
            
            @Override
            public void onFailure(Call<PostFileResult> call, Throwable t) {
                Log.d(TAG, "onFailure --> " + t.toString());
            }
        });
    }
    ```



#### 3. 结果

1. 结果截图：

    ![image-20220218232428799](image-20220218232428799.png)



### 9. 用 @FormUrlEncoded 和 @Field 注解来上传表单数据

#### 1. 过程

1. 在接口方法参数中，`@Field("key") String value` 来定义键和传入值。

2. @FormUrlEncoded 表示提交的数据是表单数据，这个必不可少。

3. 服务器接口参数：

    ![image-20220218233255987](image-20220218233255987.png)



#### 2. 代码

1. 接口方法定义：

    ```java
    @POST("/login")
    @FormUrlEncoded
    Call<LoginResult> doLogin(@Field("userName") String userName, @Field("password") String word);
    ```

2. 逻辑方法：

    ```java
    public void doLogin(View view) {
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        Call<LoginResult> loginResultCall = api.doLogin("EndlessShw", "123456");
        loginResultCall.enqueue(new Callback<LoginResult>() {
            @Override
            public void onResponse(Call<LoginResult> call, Response<LoginResult> response) {
                int code = response.code();
                Log.d(TAG, "code == " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "result --> " + response.body());
                }
            }
            @Override
            public void onFailure(Call<LoginResult> call, Throwable t) {
                Log.d(TAG, "onFailure... " + t.toString());
            }
        });
    }
    ```



#### 3. 结果

1. 结果截图：

    ![image-20220218233409215](image-20220218233409215.png)



### 10. 用 @FieldMap 上传表单数据的 Map（用 Map 来保存多个键值对）

#### 1. 代码

1. 接口方法的定义：

    ```java
    @POST("/login")
    @FormUrlEncoded
    Call<LoginResult> doLogin(@FieldMap Map<String, String> params);
    ```

2. 逻辑方法：

    ```java
    public void doLogin(View view) {
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        
        Map<String, String> params = new HashMap<>();
        params.put("userName", "Endless");
        params.put("password", "123789");
        
        Call<LoginResult> loginResultCall = api.doLogin(params);
        loginResultCall.enqueue(new Callback<LoginResult>() {
            @Override
            public void onResponse(Call<LoginResult> call, Response<LoginResult> response) {
                int code = response.code();
                Log.d(TAG, "code == " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    Log.d(TAG, "result --> " + response.body());
                }
            }
            
            @Override
            public void onFailure(Call<LoginResult> call, Throwable t) {
                Log.d(TAG, "onFailure... " + t.toString());
            }
        });
    }
    ```



#### 2. 结果

1. 结果截图：

    ![image-20220218233801057](image-20220218233801057.png)



### 11. 用 @Streaming 注解来下载文件

#### 1. 过程

1. 这里下载的 Url 是变化的，因此要用 @Url 来指定具体的 Url。
2. @Streaming 表示返回体可以获得一个输入流



#### 2. 代码

1. 接口方法定义：

    ```java
    @Streaming
    @GET
    Call<ResponseBody> downloadFile(@Url String url);
    ```

2. 逻辑方法：

    ```java
    public void downloadFile(View view) {
        Random random = new Random();
        int nextInt = random.nextInt(17);
        String Url = "/download/" + nextInt;
        Retrofit retrofit = RetrofitManager.getRetrofit();
        Api api = retrofit.create(Api.class);
        
        Call<ResponseBody> responseBodyCall = api.downloadFile(Url);
        responseBodyCall.enqueue(new Callback<ResponseBody>() {
            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {
                int code = response.code();
                Log.d(TAG, "code === " + code);
                if (code == HttpURLConnection.HTTP_OK) {
                    // 获得文件名称 --- 在 header 中
                    Headers headers = response.headers();
                    for (int i = 0; i < headers.size(); i++) {
                        String key = headers.name(i);
                        String value = headers.value(i);
                        Log.d(TAG, key+ ":" + value);
                    }
                    String filenameHeader = headers.get("Content-disposition");
                    String filename = null;
                    if (filenameHeader != null) {
                        filename = filenameHeader.replace("attachment; filename=", "");
                        Log.d(TAG, "filename == " + filename);
                    }
                    // 写文件
                    if (filename != null) {
                        writeStringToDisk(response, filename);
                    }
                }
            }
            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {
                Log.d(TAG, "onFailure... " + t.toString());
            }
        });
    }
    
    private void writeStringToDisk(Response<ResponseBody> response, String filename) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                // 获得返回的输入流
                InputStream inputStream = response.body().byteStream();
                File outFileDir = RequestActivity.this.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
                File outFile = new File(outFileDir, filename);
                Log.d(TAG, "outFile --> " + outFileDir);
                try {
                    if (!outFileDir.exists()) {
                        outFileDir.mkdirs();
                    }
                    if (!outFile.exists()) {
                        outFile.createNewFile();
                    }
                    
                    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outFile));
                    BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
                    
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = bufferedInputStream.read(buffer, 0, buffer.length)) != -1) {
                        bufferedOutputStream.write(buffer, 0, length);
                    }
                    
                    bufferedOutputStream.close();
                    bufferedInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }
    ```



#### 3. 结果

1. 结果截图：

    ![image-20220218234430790](image-20220218234430790.png)



### 12. @Headers、@Header 和 @HeaderMap 注解设置请求头

#### 1. 过程

1. @headers 的 @target 是 method，也就是要放到方法上面。@header 和 @HeaderMap 的 @target 是 parameter，因此是放在方法里面
2. @Headers({"token:owengongreo", "client:android", "key:value"})
3. @Header("key") String value
4. @HeaderMap(Map<String, String> headers)



## 5. 一些网站学习

1. OkHttp：[Overview - OkHttp (square.github.io)](https://square.github.io/okhttp/)，其 Recipes 以后要好好研读
2. Retrofit：[Retrofit (square.github.io)](https://square.github.io/retrofit/)
3. 大锯哥的笔记地址和服务器地址：https://www.sunofbeach.net/c/1197725454275039232
4. Multipart：[Multipart/form-data - 简书 (jianshu.com)](https://www.jianshu.com/p/e810d1799384)
