---
title: RecyclerView
categories:
- Android
- Basic principle
tags:
- Android
date: 2024-01-20 11:34:14
---

# RecyclerView

## 1. 构件眉目菜单，为后面展现各种不同的样式

1. 在 res 中创建名为 menu 的 package。然后在该 package 中创建 menu.xml 文件。

2. 在 menu.xml 文件中完善代码，实现菜单。

3. 在 Activity 中重写 `onCreateOptionsMenu(Menu menu)` 方法。初始化菜单。

4. 在 Activity 中重写 `onOptionsItemSelected(@NonNull MenuItem item)` 方法，也就是设置菜单的点击事件。用 switch 来指定选中的选项。

5. menu.xml：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <menu xmlns:android="http://schemas.android.com/apk/res/android">
        <!--    一级菜单-->
        <item
            android:id="@+id/list_view"
            android:title="ListView 效果">
            <!--    二级菜单-->
            <menu>
                <item
                    android:id="@+id/list_view_vertical_standard"
                    android:title="垂直标准">
    
                </item>
                <item
                    android:id="@+id/list_view_vertical_reverse"
                    android:title="垂直反向">
    
                </item>
                <item
                    android:id="@+id/list_view_horizontal_standard"
                    android:title="水平标准">
    
                </item>
                <item
                    android:id="@+id/list_view_horizontal_reverse"
                    android:title="水平反向">
    
                </item>
            </menu>
    
        </item>
        <item
            android:id="@+id/grid_view"
            android:title="GridView 效果">
            <!--    二级菜单-->
            <menu>
                <item
                    android:id="@+id/grid_view_vertical_standard"
                    android:title="垂直标准">
    
                </item>
                <item
                    android:id="@+id/grid_view_vertical_reverse"
                    android:title="垂直反向">
    
                </item>
                <item
                    android:id="@+id/grid_view_horizontal_standard"
                    android:title="水平标准">
    
                </item>
                <item
                    android:id="@+id/grid_view_horizontal_reverse"
                    android:title="水平反向">
    
                </item>
            </menu>
    
        </item>
        <item
            android:id="@+id/stagger_view"
            android:title="瀑布流效果">
            <!--    二级菜单-->
            <menu>
                <item
                    android:id="@+id/stagger_view_vertical_standard"
                    android:title="垂直标准">
    
                </item>
                <item
                    android:id="@+id/stagger_view_vertical_reverse"
                    android:title="垂直反向">
    
                </item>
                <item
                    android:id="@+id/stagger_view_horizontal_standard"
                    android:title="水平标准">
    
                </item>
                <item
                    android:id="@+id/stagger_view_horizontal_reverse"
                    android:title="水平反向">
    
                </item>
            </menu>
    
        </item>
    </menu>
    ```

    ![image-20220210000358061](image-20220210000358061.png)

    `onCreateOptionsMenu(Menu menu)` 和 `onOptionsItemSelected(@NonNull MenuItem item)`（部分） ：
    
    ```java
    @Override
        public boolean onCreateOptionsMenu(Menu menu) {
            // 在 res 中创建 menu directory，然后在其中创建 menu.xml 文件，里面设置一级、二级菜单的效果
            getMenuInflater().inflate(R.menu.menu, menu);
            return super.onCreateOptionsMenu(menu);
        }
    
        /**
         * 设置菜单的点击事件
         *
         * @param item
         * @return
         */
        @Override
        public boolean onOptionsItemSelected(@NonNull MenuItem item) {
            int itemId = item.getItemId();
            switch (itemId) {
                // ListView 部分
                case R.id.list_view_vertical_standard:
                    Log.d(TAG, "list_view_vertical_standard_btn is clicked...");
                    break;
                case R.id.list_view_vertical_reverse:
                    Log.d(TAG, "list_view_vertical_reverse_btn is clicked...");
                    break;
                case R.id.list_view_horizontal_standard:
                    Log.d(TAG, "list_view_horizontal_standard_btn is clicked...");
                    break;
                case R.id.list_view_horizontal_reverse:
                    Log.d(TAG, "list_view_horizontal_reverse is clicked...");
                    break;
    
                // GridView 部分
                case R.id.grid_view_vertical_standard:
                    break;
                case R.id.grid_view_vertical_reverse:
                    break;
                case R.id.grid_view_horizontal_standard:
                    break;
                case R.id.grid_view_horizontal_reverse:
                    break;
    
                // 瀑布流部分
                case R.id.stagger_view_vertical_standard:
                    break;
                case R.id.stagger_view_vertical_reverse:
                    break;
                case R.id.stagger_view_horizontal_standard:
                    break;
                case R.id.stagger_view_horizontal_reverse:
                    break;
    
            }
            return super.onOptionsItemSelected(item);
        }
    ```



## 2. RecyclerView 基本使用

1. 在主控件中添加 RecyclerView（例如在 activity_main.xml 中 添加）

2. 在对应的代码层中找到控件（`this.findViewById(R.id.xxx)`）

3. 准备数据（创建并初始化数据集合（例如 List），元素一般为 JavaBean 类）

4. 设置一个布局管理器（例如 LinearLayoutManager）

5. 创建适配器（继承 RecyclerView.Adapter<ListViewAdapter.InnerHolder>，里面的 InnerHolder 要自己定义并继承 RecyclerView.ViewHolder）

6. 实现适配器内的方法（重写和自定义 Holder）

7. 设置 RecyclerView 的适配器即可（`RecyclerView.setAdapter(listViewAdaper)`）

8. MainActivity.java（部分）：

    ```java
    package com.example.recyclerviewtest;
    
    import androidx.annotation.NonNull;
    import androidx.appcompat.app.AppCompatActivity;
    import androidx.recyclerview.widget.GridLayoutManager;
    import androidx.recyclerview.widget.LinearLayoutManager;
    import androidx.recyclerview.widget.RecyclerView;
    
    import android.os.Bundle;
    import android.util.Log;
    import android.view.Menu;
    import android.view.MenuItem;
    import android.widget.LinearLayout;
    
    import com.example.Adapter.GridViewAdapter;
    import com.example.Adapter.ListViewAdapter;
    import com.example.beans.ItemBean;
    import com.example.utils.Datas;
    
    import java.util.ArrayList;
    import java.util.List;
    
    /**
     * RecyclerView 总结：
     * 1. 首先要有控件，目前 RecyclerView 已经整合在 Androidx 中。
     * 2. 找到控件（findViewById）
     * 3. 准备数据（创建并初始化数据集合）
     * 4. 设置一个布局管理器
     * 5. 创建适配器
     * 6. 完善适配器的内容（包括自定义 viewHolder 等）
     * 7. 设置 RecyclerView 的适配器
     */
    public class MainActivity extends AppCompatActivity {
    
        private static final String TAG = "MainActivity";
        private RecyclerView mRecyclerView;
        private List<ItemBean> mDatas;
    
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
    
            // 初始化控件
            initView();
    
            // 准备数据，其中默认显示样式为 listView
            initData();
        }
    
        /**
         * 一般来说，在现实开发中，数据都是从网络中获取。这里只是演示。
         * 在现实开发中也是要模拟数据。例如后台没有准备好的时候。
         * 这个方法用于模拟数据
         */
        private void initData() {
            // List<DataBean>--->Adapter--->setAdapter--->显示数据
            // 创建数据集合
            mDatas = new ArrayList<>();
            // 创建模拟数据集合
            for (int i = 0; i < Datas.icons.length; i++) {
                // 创建数据对象
                ItemBean data = new ItemBean();
                data.icon = Datas.icons[i];
                data.title = "我是第" + i + "个条目";
                // 添加到数据集合里面
                mDatas.add(data);
            }
            // 默认显示样式为 listView
            showList(true, false);
        }
    
        private void initView() {
            mRecyclerView = this.findViewById(R.id.recycler_view);
            // 设置 RecyclerView 的缓存，不设置的话，每 9 个就会发生重复
            //Set the number of offscreen views to retain before adding them to the potentially shared
            mRecyclerView.setItemViewCacheSize(500);
        }
    
        @Override
        public boolean onCreateOptionsMenu(Menu menu) {
            // 在 res 中创建 menu directory，然后在其中创建 menu.xml 文件，里面设置一级、二级菜单的效果
            getMenuInflater().inflate(R.menu.menu, menu);
            return super.onCreateOptionsMenu(menu);
        }
    
        /**
         * 设置菜单的点击事件
         *
         * @param item
         * @return
         */
        @Override
        public boolean onOptionsItemSelected(@NonNull MenuItem item) {
            int itemId = item.getItemId();
            switch (itemId) {
                // ListView 部分
                case R.id.list_view_vertical_standard:
                    Log.d(TAG, "list_view_vertical_standard_btn is clicked...");
                    showList(true, false);
                    break;
                case R.id.list_view_vertical_reverse:
                    Log.d(TAG, "list_view_vertical_reverse_btn is clicked...");
                    showList(true, true);
                    break;
                case R.id.list_view_horizontal_standard:
                    Log.d(TAG, "list_view_horizontal_standard_btn is clicked...");
                    showList(false, false);
                    break;
                case R.id.list_view_horizontal_reverse:
                    Log.d(TAG, "list_view_horizontal_reverse is clicked...");
                    showList(false, true);
                    break;
    
                // GridView 部分
                case R.id.grid_view_vertical_standard:
                    showGrid(true, false);
                    break;
                case R.id.grid_view_vertical_reverse:
                    showGrid(true, true);
                    break;
                case R.id.grid_view_horizontal_standard:
                    showGrid(false, false);
                    break;
                case R.id.grid_view_horizontal_reverse:
                    showGrid(false, true);
                    break;
    
                // 瀑布流部分
                case R.id.stagger_view_vertical_standard:
                    break;
                case R.id.stagger_view_vertical_reverse:
                    break;
                case R.id.stagger_view_horizontal_standard:
                    break;
                case R.id.stagger_view_horizontal_reverse:
                    break;
    
            }
            return super.onOptionsItemSelected(item);
        }
    
        /**
         *  这个方法用于实现和 GridView 一样的效果
         */
        private void showGrid(boolean isVertical, boolean isReverse) {
            // 创建布局管理器
            GridLayoutManager gridLayoutManager = new GridLayoutManager(this, 2);
            gridLayoutManager.setOrientation(isVertical ? GridLayoutManager.VERTICAL : GridLayoutManager.HORIZONTAL);
            gridLayoutManager.setReverseLayout(isReverse);
            mRecyclerView.setLayoutManager(gridLayoutManager);
    
            // 创建适配器
            GridViewAdapter gridViewAdapter = new GridViewAdapter(mDatas);
            // 设置适配器
            mRecyclerView.setAdapter(gridViewAdapter);
        }
    
        /**
         * 这个方法用于显示 listView 一样的效果
         */
        private void showList(boolean isVertical, boolean isReverse) {
            // RecyclerView 需要设置样式，也就是设置布局管理器
            LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
            // 设置水平还是垂直
            // 找到函数的使用方法，然后找到给定的变量来源，右键选中 copyReference
            linearLayoutManager.setOrientation(isVertical ? LinearLayoutManager.VERTICAL : LinearLayoutManager.HORIZONTAL);
            // 设置标准（正向）还是标准（反向）
            linearLayoutManager.setReverseLayout(isReverse);
            mRecyclerView.setLayoutManager(linearLayoutManager);
    
            // 创建适配器
            ListViewAdapter listViewAdapter = new ListViewAdapter(mDatas);
            // 设置到 RecyclerView 里面
            mRecyclerView.setAdapter(listViewAdapter);
        }
    }
    ```

9. ListViewAdapter.java：

    ```java
    package com.example.Adapter;
    
    import android.util.Log;
    import android.view.View;
    import android.view.ViewGroup;
    import android.widget.ImageView;
    import android.widget.TextView;
    
    import androidx.annotation.NonNull;
    import androidx.recyclerview.widget.RecyclerView;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class ListViewAdapter extends RecyclerView.Adapter<ListViewAdapter.InnerHolder> {
    
        private static final String TAG = "ListViewAdapter";
        private final List<ItemBean> mDatas;
        private ImageView mIconView;
        private TextView mTitleView;
    
        /**
         * 构造函数，传入数据集合
         *
         * @param datas 传入的数据集合
         */
        public ListViewAdapter(List<ItemBean> datas) {
            mDatas = datas;
        }
    
        /**
         * 这个方法用于创建条目（也就是 RecyclerView 的单个条目），为每个条目（item_list_view） inflate 出一个 View
         * 以便将其中的控件初始化
         *
         * @param parent
         * @param viewType
         * @return
         */
        @NonNull
        @Override
        public ListViewAdapter.InnerHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            // 两个步骤
            // 1. 拿到 view
            // 2. 创建 InnerHolder
            View view = View.inflate(parent.getContext(), R.layout.item_list_view, null);
            // 传入条目的界面
            return new InnerHolder(view);
        }
    
        /**
         * 该方法调用内部 holder 类来设置数据以在特定的地方展示特定数据
         * 这个方法应该更新每一个 item 的内容
         *
         * @param holder
         * @param position
         */
        @Override
        public void onBindViewHolder(final ListViewAdapter.InnerHolder holder, int position) {
            // 设置数据
            Log.d(TAG, "position === " + position);
            holder.setData(mDatas.get(position));
    
        }
    
        /**
         * 返回条目的个数
         *
         * @return
         */
        @Override
        public int getItemCount() {
            if (mDatas != null) {
                return mDatas.size();
            }
            return 0;
        }
    
    
        /**
         * RecyclerView 包含多个 item_list_view
         * 将每一个 item_list_view 进行封装。
         * 在 InnerHolder 内实现对每个 item（条目）的数据设置或其他方法
         */
        public class InnerHolder extends RecyclerView.ViewHolder {
    
            /**
             * @param itemView 传进去的这个 View 就是单个条目的界面
             */
            public InnerHolder(View itemView) {
                super(itemView);
                // 找到条目的控件
                mIconView = itemView.findViewById(R.id.item_icon);
                mTitleView = itemView.findViewById(R.id.item_title);
    
            }
    
            /**
             * 这个方法用于设置数据
             *
             * @param itemBean
             */
            public void setData(ItemBean itemBean) {
                mIconView.setImageResource(itemBean.icon);
                mTitleView.setText(itemBean.title);
            }
        }
    }
    ```

10. GridViewAdapter.java：

    ```java
    package com.example.Adapter;
    
    import android.view.View;
    import android.view.ViewGroup;
    import android.widget.ImageView;
    import android.widget.TextView;
    
    import androidx.annotation.NonNull;
    import androidx.recyclerview.widget.RecyclerView;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class GridViewAdapter extends RecyclerView.Adapter<GridViewAdapter.InnerHolder> {
    
        private final List<ItemBean> mDatas;
    
        public GridViewAdapter(List<ItemBean> data) {
            this.mDatas = data;
        }
    
        @NonNull
        @Override
        public InnerHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
    
            // 创建条目
            View view = View.inflate(parent.getContext(), R.layout.item_grid_view, null);
            return new InnerHolder(view);
        }
    
        @Override
        public void onBindViewHolder(@NonNull InnerHolder holder, int position) {
            holder.setData(mDatas.get(position));
        }
    
        @Override
        public int getItemCount() {
            if (mDatas != null) {
                return mDatas.size();
            }
            return 0;
        }
    
        public class InnerHolder extends RecyclerView.ViewHolder {
    
            private ImageView mImageView;
            private TextView mTextView;
    
            public InnerHolder(@NonNull View itemView) {
                super(itemView);
                mImageView = itemView.findViewById(R.id.item_grid_view_icon);
                mTextView = itemView.findViewById(R.id.item_grid_view_title);
            }
    
            public void setData(ItemBean itemBean) {
                mImageView.setImageResource(itemBean.icon);
                mTextView.setText(itemBean.title);
            }
        }
    }
    ```

11. ItenBeam：

    ```java
    package com.example.beans;
    
    public class ItemBean {
        // 正常情况下是设置为私有成员，然后生成 bean 方法（get、set）
        public int icon;
        public String title;
    }
    ```

12. Datas.java：

    ```java
    package com.example.utils;
    
    import com.example.recyclerviewtest.R;
    
    public class Datas {
        public static int[] icons = {
                R.mipmap.pic_00,
                R.mipmap.pic_01,
                R.mipmap.pic_02,
                R.mipmap.pic_03,
                R.mipmap.pic_04,
                R.mipmap.pic_05,
                R.mipmap.pic_06,
                R.mipmap.pic_07,
                R.mipmap.pic_08,
                R.mipmap.pic_09,
                R.mipmap.pic_10,
                R.mipmap.pic_11,
                R.mipmap.pic_12,
                R.mipmap.pic_13,
                R.mipmap.pic_14,
                R.mipmap.pic_15,
        };
    }
    ```

13. item_list_view.xml（这里要记住 CardView 的一些属性）：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        android:layout_width="match_parent"
        android:layout_height="wrap_content">
    
        <androidx.cardview.widget.CardView
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:background="#fff000"
            app:cardBackgroundColor="#f6fDf0"
            app:cardCornerRadius="5dp"
            app:cardElevation="7dp"
            app:cardUseCompatPadding="true">
    
            <RelativeLayout
                android:layout_width="match_parent"
                android:layout_height="110dp">
    
                <ImageView
                    android:id="@+id/item_icon"
                    android:layout_width="120dp"
                    android:layout_height="90dp"
                    android:layout_margin="10dp"
                    android:scaleType="fitXY"
                    android:src="@mipmap/pic_12" />
    
                <TextView
                    android:id="@+id/item_title"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_centerVertical="true"
                    android:layout_marginLeft="20dp"
                    android:layout_toRightOf="@+id/item_icon"
                    android:text="我是标题"
                    android:textSize="25sp" />
    
            </RelativeLayout>
    
        </androidx.cardview.widget.CardView>
    
    </RelativeLayout>
    ```

    ![image-20220210000921309](image-20220210000921309.png)

14. item_grid_view.xml：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        android:layout_width="match_parent"
        android:layout_height="match_parent">
    
        <androidx.cardview.widget.CardView
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:background="#fff000"
            app:cardBackgroundColor="#f6fDf0"
            app:cardCornerRadius="2dp"
            app:cardElevation="7dp"
            app:cardUseCompatPadding="true">
    
            <RelativeLayout
                android:layout_width="wrap_content"
                android:layout_height="wrap_content">
    
                <ImageView
                    android:id="@+id/item_icon"
                    android:layout_width="200dp"
                    android:layout_height="140dp"
                    android:layout_centerHorizontal="true"
                    android:layout_marginTop="10dp"
                    android:scaleType="fitXY"
                    android:src="@mipmap/pic_00" />
    
                <TextView
                    android:id="@+id/item_title"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_below="@+id/item_icon"
                    android:layout_marginTop="20dp"
                    android:text="我是一个标题"
                    android:textSize="25sp" />
    
            </RelativeLayout>
    
        </androidx.cardview.widget.CardView>
    
    </RelativeLayout>
    ```

    ![image-20220210001010684](image-20220210001010684.png)



## 3. 重构 Adapter

1. 由上面的两个 adapter 可以看出，代码大致相同，因此可以重构。

2. 重构的思路是：

    1. 既然两个 adapter 的代码大致相同，那么抽象出一个父类，两个 adapter 分别继承他
    2. 这样做，MainActivity 中的代码可以不用改变。
    3. 由于两个 adapter 操作的 item 不同，因此抽象出来的父类抽象定义方法，作用是获得具体的 item，然后具体的实现过程交给两个子类 adapter 实现。
    4. 注意保留两个子类的构造函数。

3. 抽象父类 RecyclerViewBaseAdapter.java：

    ```java
    package com.example.Adapter;
    
    import android.view.View;
    import android.view.ViewGroup;
    import android.widget.ImageView;
    import android.widget.TextView;
    
    import androidx.annotation.NonNull;
    import androidx.recyclerview.widget.RecyclerView;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    // 抽象类无法被实例化。但是可以实现方法
    public abstract class RecyclerViewBaseAdapter extends RecyclerView.Adapter<RecyclerViewBaseAdapter.InnerHolder> {
    
        private final List<ItemBean> mDatas;
    
        public RecyclerViewBaseAdapter(List<ItemBean> datas) {
            this.mDatas = datas;
        }
    
        @NonNull
        @Override
        public InnerHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = getSubView(parent, viewType);
            return new InnerHolder(view);
        }
    
        protected abstract View getSubView(View parent, int viewType);
    
        @Override
        public void onBindViewHolder(@NonNull InnerHolder holder, int position) {
            // 在这里绑定数据
            holder.setData(mDatas.get(position));
        }
    
    
        @Override
        public int getItemCount() {
            if (mDatas != null) {
                return mDatas.size();
            }
            return 0;
        }
    
        public class InnerHolder extends RecyclerView.ViewHolder {
    
            private ImageView mIconView;
            private TextView mTitleView;
    
    
            /**
             * @param itemView 传进去的这个 View 就是单个条目的界面
             */
            public InnerHolder(View itemView) {
                super(itemView);
                // 找到条目的控件
                mIconView = itemView.findViewById(R.id.item_icon);
                mTitleView = itemView.findViewById(R.id.item_title);
    
            }
    
            /**
             * 这个方法用于设置数据
             *
             * @param itemBean
             */
            public void setData(ItemBean itemBean) {
                mIconView.setImageResource(itemBean.icon);
                mTitleView.setText(itemBean.title);
            }
        }
    }
    ```

4. ListViewAdapter.java：

    ```java
    package com.example.Adapter;
    
    import android.view.View;
    import android.widget.ImageView;
    import android.widget.TextView;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class ListViewAdapter extends RecyclerViewBaseAdapter {
    
        private static final String TAG = "ListViewAdapter";
        private ImageView mIconView;
        private TextView mTitleView;
    
        /**
         * 构造函数，传入数据集合
         *
         * @param datas 传入的数据集合
         */
        public ListViewAdapter(List<ItemBean> datas) {
            super(datas);
        }
    
        @Override
        protected View getSubView(View parent, int viewType) {
            // 两个步骤
            // 1. 拿到 view
            // 2. 创建 InnerHolder
            View view = View.inflate(parent.getContext(), R.layout.item_list_view, null);
            // 传入条目的界面
            return view;
        }
    }
    ```

5. GridViewAdapter.java：

    ```java
    package com.example.Adapter;
    
    import android.view.View;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class GridViewAdapter extends RecyclerViewBaseAdapter {
    
        public GridViewAdapter(List<ItemBean> datas) {
            super(datas);
        }
    
        @Override
        protected View getSubView(View parent, int viewType) {
            // 创建条目
            View view = View.inflate(parent.getContext(), R.layout.item_grid_view, null);
            return view;
        }
    }
    ```


6. 类似 ListView 效果（垂直标准）：

    ![image-20220210000553840](image-20220210000553840.png)

    类似 GridView 效果（垂直标准）：

    ![image-20220210000624441](image-20220210000624441.png)



## 4. 实现瀑布流

1. 创建瀑布流的 item：item_stagger_view.xml

2. 和其他两个一样（ListView、GridView），创建 adapter、设置布局管理器和适配器。

3. item_stagger_view.xml：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        android:layout_width="match_parent"
        android:layout_height="match_parent">
    
        <androidx.cardview.widget.CardView
            android:layout_width="match_parent"
            android:layout_height="match_parent"
            app:cardBackgroundColor="#f6fDf0"
            app:cardCornerRadius="3dp"
            app:cardElevation="4dp"
            app:cardUseCompatPadding="true">
    
            <RelativeLayout
                android:layout_width="match_parent"
                android:layout_height="match_parent">
    
                <ImageView
                    android:id="@+id/item_icon"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_centerHorizontal="true"
                    android:adjustViewBounds="true"
                    android:maxWidth="250dp"
                    android:maxHeight="250dp"
                    android:padding="5dp"
                    android:scaleType="centerCrop"
                    android:src="@mipmap/pic_00" />
    
                <TextView
                    android:id="@+id/item_title"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_below="@+id/item_icon"
                    android:layout_centerHorizontal="true"
                    android:layout_marginTop="12dp"
                    android:text="我是标题"
                    android:textSize="20sp" />
    
            </RelativeLayout>
    
        </androidx.cardview.widget.CardView>
    
    </RelativeLayout>
    ```

    ![image-20220210000732137](image-20220210000732137.png)

4. showStagger，就是实现瀑布流效果的方法：

    ```java
    /**
         * 这个方法用于实现瀑布流的效果
         *
         * @param isVertical 是否垂直
         * @param isReverse  是否反转
         */
        private void showStagger(boolean isVertical, boolean isReverse) {
            // 准备布局管理器
            StaggeredGridLayoutManager staggeredGridLayoutManager = new StaggeredGridLayoutManager(2,
                    isVertical ? StaggeredGridLayoutManager.VERTICAL : StaggeredGridLayoutManager.HORIZONTAL);
            // 设置方向
            staggeredGridLayoutManager.setReverseLayout(isReverse);
            // 设置布局管理器
            mRecyclerView.setLayoutManager(staggeredGridLayoutManager);
    
            // 创建适配器
            mAdapter = new StaggerViewAdapter(mDatas);
            // 设置适配器
            mRecyclerView.setAdapter(mAdapter);
    
        }
    ```

5. StaggerViewAdapter.java：

    ```java
    package com.example.Adapter;
    
    import android.view.View;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class StaggerViewAdapter extends RecyclerViewBaseAdapter {
    
        public StaggerViewAdapter(List<ItemBean> datas) {
            super(datas);
        }
    
        @Override
        protected View getSubView(View parent, int viewType) {
            View view = View.inflate(parent.getContext(), R.layout.item_stagger_view, null);
            return view;
        }
    }
    ```


6. 瀑布流效果：

    ![image-20220210001151559](image-20220210001151559.png)



## 5. 设置点击事件

### 1. 思路

1. 和其他按钮等能触发监听事件的一样，每个 adapter 也应该可以设置一个监听器。
2. 编写回调接口和方法，将回调方法的具体实现交给设置 adapter 的外部来决定（和设置按钮事件一样）。同时也需要给外界提供一个设置接口的方法，因为外部通过该方法传入一个实现了回调方法的回调接口后，内部的 adapter 就可以用这个传入的接口去调用实现的方法。
3. 由于 RecyclerView 的每一个组件都是由 item 组成的，因此在每个 item 中设置各自的点击事件 `itemView.setOnClickListener(new View.OnClickListener(){ @Overridr onClick(View v)}`。各自的点击事件中，调用回调接口的回调方法。



### 2. 代码

1. RecyclerViewBaseAdapter.java---接口：

    ```java
    /**
     * 编写回调的步骤
     * 1. 创建接口
     * 2. 定义接口内部的方法
     * 3. 提供一个设置接口的方法
     * 4. 接口方法的调用
     */
    public interface OnItemClickListener{
        // 借鉴 ListView 的 onItemClick。从 ListView 向上找，搜索。
        // 这里的 onItemClick 交给外部实现，也就是回调方法
        void onItemClick(int position);
    }
    /**
     * 提供一个设置接口的方法，由外部决定设置什么接口（外部可以定义多个接口，实现接口内方法的不同逻辑，从而触发不同的事件）
     */
    
    public void setOnItemClickListener(OnItemClickListener listener) {
        // 设置一个监听，本质上就是要设置一个回调接口
        this.mOnItemClickListener = listener;
    }
    ```

2. InnerHolder 的修改：

    ```java
    public class InnerHolder extends RecyclerView.ViewHolder {
        
        private ImageView mIconView;
        private TextView mTitleView;
        // 一定要放在 InnerHolder 而不是最外层，每一个 InnerHolder 都有自己的 position
        private int mPosition;
        
        /**
         * @param itemView 传进去的这个 View 就是单个条目的界面
         */
        public InnerHolder(View itemView) {
            super(itemView);
            // 找到条目的控件
            mIconView = itemView.findViewById(R.id.item_icon);
            mTitleView = itemView.findViewById(R.id.item_title);
            
            /**
             * 为每一个 item 设置各自的点击事件
             */
            itemView.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (mOnItemClickListener != null) {
                        // 把被点击的那一个的编号传出去，有利于定位
                        mOnItemClickListener.onItemClick(mPosition);
                    }
                }
            });
        }
        
        /**
         * 这个方法用于设置数据
         *
         * @param itemBean
         */
        public void setData(ItemBean itemBean, int position) {
            // 临时保存 position
            this.mPosition = position;
            mIconView.setImageResource(itemBean.icon);
            mTitleView.setText(itemBean.title);
        }
    }
    ```




### 3. 效果

1. 效果图：

    ![image-20220210001244826](image-20220210001244826.png)



## 6. RecyclerView 实现多条目类型

### 1. 大致思路

1. 由于实现的界面和前面三个略微不同，因此创建一个新的 Activity---MultiTypeActivity.java
2. 创建 activity_multi_type.xml，实现 RecyclerView
3. 初始化控件、数据以及设置布局管理器
4. 创建 adapter---MultiTypeViewAdapter。要注意的是，由于是多条目，因此每个条目都要创建自己的 Item，与此同时，继承的 RecyclerView.Adapter 也不要指定具体的 InnerHolder(继承 ViewHolder)。
5. 实现方法。由于 Item 有多个类型，因此 InnerHolder 也要有多个类型一一对应。因此 `onCreateViewHolder(ViewGroup parent, int ViewType)` 返回的 InnerHolder 也要根据 ViewType 来确定。
6. ViewType 的确定取决于方法 `getItemViewType(int position)`，未重写时默认都返回 0，因此要复写它，让其返回一个条目类型值（自己定义常量）以确定是哪一个条目。
7. 条目类型应该定义在 JavaBean 中，这样`getItemViewType(int position)` 就可以根据 JavaBean 中的类型返回条目类型值给 ViewType（或者当时定义的时候就用常量，然后在 `getItemViewType(int position)` 中用 get 方法取出类型值并返回。



### 2. 代码

1. MultiTypeActivity.java：

    ```java
    package com.example.recyclerviewtest;
    
    import androidx.appcompat.app.AppCompatActivity;
    import androidx.recyclerview.widget.LinearLayoutManager;
    import androidx.recyclerview.widget.RecyclerView;
    
    import android.os.Bundle;
    
    import com.example.Adapter.MultiTypeViewAdapter;
    import com.example.beans.MultiTypeItemBean;
    import com.example.utils.Datas;
    
    import java.util.ArrayList;
    import java.util.List;
    import java.util.Random;
    
    public class MultiTypeActivity extends AppCompatActivity {
    
        private RecyclerView mRecyclerView;
        private List<MultiTypeItemBean> mDatas;
    
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_multi_type);
    
            initView();
    
            initData();
    
            show();
        }
    
        private void show() {
            LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
            mRecyclerView.setLayoutManager(linearLayoutManager);
    
            MultiTypeViewAdapter multiTypeViewAdapter = new MultiTypeViewAdapter(mDatas);
            mRecyclerView.setAdapter(multiTypeViewAdapter);
        }
    
        private void initData() {
            mDatas = new ArrayList<>();
    
            Random random = new Random();
    
            for (int i = 0; i < Datas.icons.length; i++) {
                MultiTypeItemBean data = new MultiTypeItemBean();
                data.pic = Datas.icons[i];
                // 随机指定类型，范围 [0,3)
                data.type = random.nextInt(3);
                mDatas.add(data);
            }
    
        }
    
        private void initView() {
            mRecyclerView = this.findViewById(R.id.multi_type_recycler_view);
        }
    }
    ```

2. activity_multi_type：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:tools="http://schemas.android.com/tools"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        tools:context=".MultiTypeActivity"
        android:orientation="vertical" >
    
        <androidx.recyclerview.widget.RecyclerView
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:id="@+id/multi_type_recycler_view" >
    
        </androidx.recyclerview.widget.RecyclerView>
    
    </LinearLayout>
    ```

3. 三种条目类型 item 的布局（不太完善）：

    1. item_type_full_image.xml：

        ```xml
        <?xml version="1.0" encoding="utf-8"?>
        <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:app="http://schemas.android.com/apk/res-auto"
            android:layout_width="match_parent"
            android:layout_height="wrap_content">
        
            <androidx.cardview.widget.CardView
                android:layout_width="match_parent"
                android:layout_height="match_parent"
                app:cardBackgroundColor="#f6fDf0"
                app:cardCornerRadius="3dp"
                app:cardElevation="4dp"
                app:cardUseCompatPadding="true">
        
                <RelativeLayout
                    android:layout_width="match_parent"
                    android:layout_height="match_parent"
                    android:padding="10dp">
        
                    <TextView
                        android:id="@+id/multi_type_title"
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:layout_centerHorizontal="true"
                        android:text="我是标题"
                        android:textSize="30sp" />
        
                    <ImageView
                        android:id="@+id/multi_type_pic"
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:layout_below="@+id/multi_type_title"
                        android:layout_centerHorizontal="true"
                        android:layout_marginTop="10dp"
                        android:adjustViewBounds="true"
                        android:scaleType="centerCrop"
                        android:src="@mipmap/pic_09" />
        
                </RelativeLayout>
        
            </androidx.cardview.widget.CardView>
        
        </RelativeLayout>
        ```

        ![image-20220210001341946](image-20220210001341946.png)

    2. item_type_left_title_right_image：

        ```xml
        <?xml version="1.0" encoding="utf-8"?>
        <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:app="http://schemas.android.com/apk/res-auto"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:gravity="center_horizontal">
        
            <androidx.cardview.widget.CardView
                android:layout_width="match_parent"
                android:layout_height="match_parent"
                app:cardBackgroundColor="#f6fDf0"
                app:cardCornerRadius="3dp"
                app:cardElevation="4dp"
                app:cardUseCompatPadding="true">
        
                <LinearLayout
                    android:layout_width="match_parent"
                    android:layout_height="match_parent">
        
                    <TextView
                        android:id="@+id/multi_type_title"
                        android:layout_width="0dp"
                        android:layout_height="wrap_content"
                        android:layout_centerVertical="true"
                        android:layout_gravity="center_vertical"
                        android:layout_weight="4"
                        android:text="我是标题"
                        android:textSize="20sp" />
        
        
                    <ImageView
                        android:id="@+id/multi_type_pic"
                        android:layout_width="0dp"
                        android:layout_height="wrap_content"
                        android:layout_marginLeft="10dp"
                        android:layout_weight="2"
                        android:adjustViewBounds="true"
                        android:scaleType="centerCrop"
                        android:src="@mipmap/pic_08" />
        
                </LinearLayout>
        
            </androidx.cardview.widget.CardView>
        
        </LinearLayout>
        ```

        ![image-20220210001408138](image-20220210001408138.png)

    3. item_type_three_images.xml：

        ```xml
        <?xml version="1.0" encoding="utf-8"?>
        <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:app="http://schemas.android.com/apk/res-auto"
            android:layout_width="match_parent"
            android:layout_height="match_parent"
            android:orientation="vertical">
        
            <androidx.cardview.widget.CardView
                android:layout_width="match_parent"
                android:layout_height="match_parent"
                app:cardBackgroundColor="#f6fDf0"
                app:cardCornerRadius="3dp"
                app:cardElevation="4dp"
                app:cardUseCompatPadding="true">
        
                <LinearLayout
                    android:layout_width="wrap_content"
                    android:layout_height="match_parent"
                    android:orientation="vertical">
        
                    <TextView
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:gravity="center_horizontal"
                        android:text="标题"
                        android:textSize="20sp" />
        
                    <LinearLayout
                        android:layout_width="match_parent"
                        android:layout_height="wrap_content"
                        android:layout_marginTop="10dp"
                        android:orientation="horizontal"
                        android:padding="5dp">
        
                        <ImageView
                            android:layout_width="0dp"
                            android:layout_height="wrap_content"
                            android:layout_gravity="center_vertical"
                            android:layout_margin="3dp"
                            android:layout_weight="1"
                            android:adjustViewBounds="true"
                            android:scaleType="fitXY"
                            android:src="@mipmap/pic_00" />
        
                        <ImageView
                            android:layout_width="0dp"
                            android:layout_height="wrap_content"
                            android:layout_gravity="center_vertical"
                            android:layout_margin="3dp"
                            android:layout_weight="1"
                            android:adjustViewBounds="true"
                            android:scaleType="fitXY"
                            android:src="@mipmap/pic_00" />
        
                        <ImageView
                            android:layout_width="0dp"
                            android:layout_height="wrap_content"
                            android:layout_gravity="center_vertical"
                            android:layout_margin="3dp"
                            android:layout_weight="1"
                            android:adjustViewBounds="true"
                            android:scaleType="fitXY"
                            android:src="@mipmap/pic_08" />
        
                    </LinearLayout>
                    
                </LinearLayout>
        
            </androidx.cardview.widget.CardView>
        
        </LinearLayout>
        ```
        
        ![image-20220210001434228](image-20220210001434228.png)

4. MultiTypeViewAdapter.java（布局使用静态的，未绑定数据等等）：

    ```java
    package com.example.Adapter;
    
    import android.view.View;
    import android.view.ViewGroup;
    
    import androidx.annotation.NonNull;
    import androidx.recyclerview.widget.RecyclerView;
    
    import com.example.beans.MultiTypeItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class MultiTypeViewAdapter extends RecyclerView.Adapter {
    
        private final List<MultiTypeItemBean> mDatas;
    
        // 定义三种常量，因为有三个类型
        public static final int TYPE_FULL_IMAGE = 0;
        public static final int TYPE_RIGHT_IMAGE = 1;
        public static final int TYPE_THREE_IMAGES = 2;
    
        public MultiTypeViewAdapter(List<MultiTypeItemBean> datas) {
            this.mDatas = datas;
        }
    
        @NonNull
        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
    
            View view;
    
            if (viewType == TYPE_FULL_IMAGE) {
                view = View.inflate(parent.getContext(), R.layout.item_type_full_image, null);
                return new FullImageHolder(view);
            } else if (viewType == TYPE_RIGHT_IMAGE) {
                view = View.inflate(parent.getContext(), R.layout.item_type_left_title_right_image, null);
                return new RightImageHolder(view);
            } else {
                view = View.inflate(parent.getContext(), R.layout.item_type_three_images, null);
                return new ThreeImageHolder(view);
            }
        }
    
        @Override
        public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
    
        }
    
        @Override
        public int getItemCount() {
            if (mDatas != null) {
                return mDatas.size();
            }
            return 0;
        }
    
        /**
         * 复写方法、这个方法是根据条目来返回条目类型
         * Return the view type of the item at <code>position</code> for the purposes
         * of view recycling.
         * 返回的类型值会传递给 onCreateViewHolder() 的 viewType 中
         */
        @Override
        public int getItemViewType(int position) {
            MultiTypeItemBean multiTypeItemBean = mDatas.get(position);
            if (multiTypeItemBean.type == 0) {
                return TYPE_FULL_IMAGE;
            } else if (multiTypeItemBean.type == 1) {
                return TYPE_RIGHT_IMAGE;
            } else {
                return TYPE_THREE_IMAGES;
            }
        }
    
        private class FullImageHolder extends RecyclerView.ViewHolder {
            public FullImageHolder(@NonNull View itemView) {
                super(itemView);
            }
        }
    
        private class RightImageHolder extends RecyclerView.ViewHolder {
            public RightImageHolder(@NonNull View itemView) {
                super(itemView);
            }
        }
    
        private class ThreeImageHolder extends RecyclerView.ViewHolder {
            public ThreeImageHolder(@NonNull View itemView) {
                super(itemView);
            }
        }
    }
    ```

    

## 7. 上下拉刷新

### 1. 下拉刷新

#### 1. 思路

1. 在布局配置文件中，将其他控件都放在 SwipeRefreshLayout 控件里面（这里是放在了 MainActivity 里面）（记得添加依赖）。
2. 在 Activity 中取出控件，设置监听。
3. 监听的思路在于：
    1. 在新的线程中执行操作
    2. 给数据组的头部添加新的数据
    3. 通知 adapter 数据已经改变
    4. 停止 SwipeRefreshLayout 的刷新状态（`SwipeRefreshLayout.setRefresh(false)`）



#### 2. 代码

1. `handlerDownPullUpdate()` 执行下拉刷新数据的操作：

    ```java
    /**
     * 执行下拉刷新数据的操作
     * 这里演示添加一条数据
     */
    private void handlerDownPullUpdate() {
        // 设置刷新时图标的颜色
        mSwipeRefreshLayout.setColorSchemeResources(R.color.teal_200, R.color.purple_500);
        mSwipeRefreshLayout.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() {
            /**
             * 这个方法在主线程 MainThread 中执行，不可执行耗时操作。
             * 因此一般要请求数据时，需要额外开一个线程去获取
             */
            @Override
            public void onRefresh() {
                ItemBean data = new ItemBean();
                data.title = "我是新添加的数据...";
                data.icon = R.mipmap.pic_15;
                // 添加到头部
                mDatas.add(0, data);
                // 更新 UI 并让刷新停止
                // 这里也可以使用 Handler().postDelayed(new Runnable(){...}) 来实现，然后可以加上刷新完后的延迟时间
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            // 先延迟 2s，模拟一个数据请求的过程
                            Thread.sleep(2000);
                            // 再更新 UI
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    // 通知 adapter 数据已经改变
                                    mAdapter.notifyDataSetChanged();
                                    // 数据更新完成，通知停止刷新
                                    mSwipeRefreshLayout.setRefreshing(false);
                                }
                            });
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                });
                thread.start();
            }
        });
    }
    ```



#### 3. 效果

1. 效果图

    ![image-20220210001612854](image-20220210001612854.png)

    ![image-20220210001625042](image-20220210001625042.png)



### 2. 上拉刷新（只实现了 ListView 类型的）

#### 1. 思路

1. 由于刷新时会多出来一个新的 item 来显示刷新加载的状态，因此由原来的一个 InnerHolder 变成两个。因此大致的思路是对 ListViewAdapter.java 进行多个方法的重写。
2. 和多条目类型的一些思路一样，既然是两个不同的 item，那么就在 ListViewAdapter 中定义两种不同的状态以区分。
3. 状态区分后，那就要重写 `getItemViewType(int position)` 方法，默认将当前的最后一个条目设置成上拉刷新加载的条目。
4. 创建上拉刷新的条目的 layout，这里将进程条控件(ProgressBar)、正在刷新的标题（TextView）这两个（放在大的 Layout 标签中）与加载失败的提示（TextView）放在一个 layout 文件中。分别取一个 id（总共两个）。三个状态控制这两个的显隐（加载中、加载失败和正常显示三个状态）。
5. 创建第二个 InnerHolder 叫 LoaderMoreHolder，里面创建三个状态、获取两个控件（id）、设置重新加载的控件的点击事件（状态由重新加载状态更新到加载中）以及状态更新（控件的可视情况）方法。（大致框架）
6. 在 RecyclerViewBaseAdapter.java 中，定义了抽象方法 `getSubView(View parent, int viewType)` 交给子类实现以获取 item 的 view。这里要对 ListViewAdapter.java 中的进行一个重构，根据类型返回不同的 item。
7. 重写 `onCreateViewHolder(ViewGroup parent, int ViewType)`。注意函数的返回值是 RecyclerView.ViewHolder（也就是两个 Holder 的父类）。注意的是，首次创建 LoaderMoreHolder 时，要设置其状态为加载中状态（因为刚刷到它的时候必然是一个上拉刷新的时候）
8. 执行上拉刷新，也就是当状态变成加载中状态时，要进行一个类似于加载数据并更新 UI 的操作。那么这些操作是要用一个方法来整合。并且由第 5 点可知，在状态更新的时候（也就是当状态变成加载中的时候，要执行这个方法）。
9. 由第 8 点可知，这又是一个监听回调的操作。和下拉刷新一样，把回调方法交给外部 Activity 实现（实现时注意：外部实现时需要实现状态更新，那么 LoaderMoreHolder 就要暴露在外面。或者将状态更新的逻辑实现放在内部实现，这样就不用暴露在外面），然后内部调用。
10. 创建接口、创建设置接口的方法、在 LoaderMoreHolder 中创建方法（`startLoadMore()`）来调用这个回调方法。然后在状态变成加载中时调用 `startLoadMore()`（也就是调用回调方法）
11. 还有一些细节在代码中展示



#### 2. 代码

1. ListViewAdapter.java 的重构：

    ```java
    package com.example.Adapter;
    
    import android.util.Log;
    import android.view.View;
    import android.view.ViewGroup;
    import android.widget.ImageView;
    import android.widget.LinearLayout;
    import android.widget.TextView;
    
    import androidx.annotation.NonNull;
    import androidx.recyclerview.widget.RecyclerView;
    
    import com.example.beans.ItemBean;
    import com.example.recyclerviewtest.R;
    
    import java.util.List;
    
    public class ListViewAdapter extends RecyclerViewBaseAdapter {
    
        // 类型，分为正常的图片类型和加载的类型
        // 普通条目类型
        public static final int TYPE_NORMAL = 0;
        // 加载条目类型
        public static final int TYPE_LOADER_MORE = 1;
    
        private static final String TAG = "ListViewAdapter";
        private ImageView mIconView;
        private TextView mTitleView;
        private OnRefreshListener mOnPullRefreshListener;
    
        /**
         * 构造函数，传入数据集合
         *
         * @param datas 传入的数据集合
         */
        public ListViewAdapter(List<ItemBean> datas) {
            super(datas);
        }
    
        /**
         * 由于有两种类型：正常图片类型和加载的类型，因此产生两个 holder，因此返回 holder 的父类 ViewHolder（特指函数）
         * 实际上返回的 holder 要根据 viewType 来确定
         * InnerHolder 在父类中（RecyclerViewBaseAdapter）中已经定义过，因此直接用即可（类型要改成 protected）
         *
         * @param parent
         * @param viewType
         * @return
         */
        @NonNull
        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            // 根据类型创建对应的 view
            View view = getSubView(parent, viewType);
    
            if (viewType == TYPE_NORMAL) {
                return new InnerHolder(view);
            } else {
                LoaderMoreHolder loaderMoreHolder = new LoaderMoreHolder(view);
                // 首次创建的时候，需要更新状态为加载中状态（也就是刚刷到底下时）
                loaderMoreHolder.update(LoaderMoreHolder.LOADER_STATE_LOADING);
                return loaderMoreHolder;
            }
    
        }
    
        /**
         * 由于产生两个 holder，因此绑定数据也得根据它的类型做出相应的改变
         *
         * @param holder
         * @param position
         */
        @Override
        public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
            // 在这里绑定数据
            // 正常图片类型就正常设置，不是的话就更改其状态为加载中状态
            if (getItemViewType(position) == TYPE_NORMAL && holder instanceof InnerHolder) {
                ((InnerHolder) holder).setData(mDatas.get(position), position);
            } else if (getItemViewType(position) == TYPE_LOADER_MORE && holder instanceof LoaderMoreHolder) {
                ((LoaderMoreHolder) holder).update(LoaderMoreHolder.LOADER_STATE_LOADING);
            }
    
        }
    
        /**
         * 根据类型创建对应的 view
         *
         * @param parent
         * @param viewType
         * @return
         */
        @Override
        protected View getSubView(View parent, int viewType) {
            View view;
            // 根据类型创建 View
            if (viewType == TYPE_NORMAL) {
                view = View.inflate(parent.getContext(), R.layout.item_list_view, null);
            } else {
                view = View.inflate(parent.getContext(), R.layout.item_list_loader_more, null);
            }
            // 传入条目的界面
            return view;
        }
    
        @Override
        public int getItemViewType(int position) {
    //        Log.d(TAG, "getItemCount() - 1 === " + (getItemCount() - 1));
    //        Log.d(TAG, "positon === " + position);
            if (position == getItemCount() - 1) {
                // 默认将当前的最后一个条目设置成特殊类型条目
                return TYPE_LOADER_MORE;
            } else return TYPE_NORMAL;
        }
    
        /**
         * 上拉刷新的接口
         */
        public interface OnRefreshListener {
            void onUpPullRefresh(LoaderMoreHolder loaderMoreHolder);
        }
    
        /**
         * 设置上拉刷新的监听接口
         */
        public void setOnRefreshListener(OnRefreshListener listener) {
            this.mOnPullRefreshListener = listener;
        }
    
        public class LoaderMoreHolder extends RecyclerView.ViewHolder {
    
            // 为了控制控件的显隐，这里需要创建状态来表示
            public static final int LOADER_STATE_LOADING = 0;
            public static final int LOADER_STATE_RELOAD = 1;
            public static final int LOADER_STATE_NORMAL = 2;
    
            private final LinearLayout mLoading;
            private final TextView mReload;
    
            public LoaderMoreHolder(@NonNull View itemView) {
                super(itemView);
    
                mLoading = itemView.findViewById(R.id.loading);
                mReload = itemView.findViewById(R.id.reload);
    
                // 当点击重新加载的控件时，需要触发重新加载的操作,也就是回到加载中的操作
                mReload.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        update(LOADER_STATE_LOADING);
                    }
                });
            }
    
    
            /**
             * 这里将控件都写在同一个文件中，根据逻辑状态来设置部分控件的可见状态。
             *
             * @param state
             */
            public void update(int state) {
    
                // 重置控件的状态，一开始都设置为不可见
                mLoading.setVisibility(View.GONE);
                mReload.setVisibility(View.GONE);
    
                switch (state) {
                    // 加载状态
                    case LOADER_STATE_LOADING:
                        mLoading.setVisibility(View.VISIBLE);
                        // 触发加载数据
                        startLoadMore();
                        break;
                    // 重新加载状态
                    case LOADER_STATE_RELOAD:
                        mReload.setVisibility(View.VISIBLE);
                        break;
                    // 正常显示状态
                    case LOADER_STATE_NORMAL:
                        mLoading.setVisibility(View.GONE);
                        mReload.setVisibility(View.GONE);
                        break;
                }
            }
    
            /**
             * 调用上拉回调方法
             */
            private void startLoadMore() {
                if (mOnPullRefreshListener != null) {
                    // 将自己传出、让回调实现方调用状态更新方法
                    mOnPullRefreshListener.onUpPullRefresh(this);
                    // 外部的状态更新以及随机都可以放在这里实现，这样就可以不暴露 LoaderMoreHolder
                }
            }
        }
    }
    ```

2. 外部监听事件的设置：

    ```java
    /**
     * 该函数内实现了各种监听事件
     */
    private void initListener() {
        
        mAdapter.setOnItemClickListener(new RecyclerViewBaseAdapter.OnItemClickListener() {
            @Override
            public void onItemClick(int position) {
                // 这里处理条目的点击事件
                Toast.makeText(MainActivity.this, "点击的是第" + position + "个条目", Toast.LENGTH_SHORT).show();
            }
        });
        
        // 处理上拉加载更多
        // 这里只写了 ListView 样式的上拉刷新
        // 设置上拉方法
        // 这里将 ListViewAdapter.LoaderMoreHolder 暴露出来，以便调用其 update 方法
        if (mAdapter instanceof ListViewAdapter) {
            ((ListViewAdapter) mAdapter).setOnRefreshListener(new ListViewAdapter.OnRefreshListener() {
                @Override
                public void onUpPullRefresh(
                        final ListViewAdapter.LoaderMoreHolder loaderMoreHolder) {
                    // 加载数据，需要在子线程中完成
                    // 更新 UI 并让刷新停止
                    // 这里也可以使用 Handler().postDelayed(new Runnable(){...}) 来实现，然后可以加上刷新完后的延迟时间
                    Thread thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                // 先延迟 2s，模拟一个数据请求的过程
                                Thread.sleep(2000);
                                // 再更新 UI
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        // 模拟加载失败
                                        Random random = new Random();
                                        if (random.nextInt() % 2 == 0) {
                                            ItemBean data = new ItemBean();
                                            data.title = "我是上拉添加的数据...";
                                            data.icon = R.mipmap.pic_14;
                                            // 添加到尾部
                                            // 这样子可以一次性将所有的 mDatas 的内容显示出来
                                            if (mDatas.get(mDatas.size() - 1) == null) {
                                                mDatas.set(mDatas.size() - 1, data);
                                            } else {
                                                mDatas.add(data);
                                            }
                                            // 通知 adapter 数据已经改变
                                            mAdapter.notifyDataSetChanged();
                                            // 数据更新完成，通知停止刷新
                                            // 这里的状态更新以及随机都可以放在内部实现，这样就可以不暴露 LoaderMoreHolder
                                            loaderMoreHolder.update(ListViewAdapter.LoaderMoreHolder.LOADER_STATE_NORMAL);
                                        } else {
                                            loaderMoreHolder.update(ListViewAdapter.LoaderMoreHolder.LOADER_STATE_RELOAD);
                                        }
                                    }
                                });
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    });
                    thread.start();
                }
            });
        }
    ```

3. 相应的，`showList(boolean isVertical, boolean isReverse)` 的重构：

    ```java
    /**
     * 这个方法用于显示 listView 一样的效果
     */
    private void showList(boolean isVertical, boolean isReverse) {
        // RecyclerView 需要设置样式，也就是设置布局管理器
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
        // 设置水平还是垂直
        // 找到函数的使用方法，然后找到给定的变量来源，右键选中 copyReference
        linearLayoutManager.setOrientation(isVertical ? LinearLayoutManager.VERTICAL : LinearLayoutManager.HORIZONTAL);
        // 设置标准（正向）还是标准（反向）
        linearLayoutManager.setReverseLayout(isReverse);
        mRecyclerView.setLayoutManager(linearLayoutManager);
        // 创建适配器
        if (mDatas.get(mDatas.size() - 1) != null) {
            // 如果倒数第一个不是 null，那么添加一个 null 到列表里面，当上拉刷新的时候，删除空的并添加即可
            // 这样做保证结尾不会有两个或以上连续的 null
            mDatas.add(null);
        }
        mAdapter = new ListViewAdapter(mDatas);
        // 设置到 RecyclerView 里面
        mRecyclerView.setAdapter(mAdapter);
        // 创建监听事件
        initListener();
    }
    ```

4. 加载中和加载失败重新加载的 layout 文件---item_list_loader_more.xml：

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        android:layout_width="match_parent"
        android:layout_height="wrap_content">
    
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
                android:orientation="vertical">
    
                <!--这部分是加载的部分，一个圆圈和一个 title-->
    
                <LinearLayout
                    android:id="@+id/loading"
                    android:layout_width="match_parent"
                    android:layout_height="110dp"
                    android:gravity="center_vertical"
                    android:orientation="horizontal">
    
                    <ProgressBar
                        android:padding="20dp"
                        android:layout_width="100dp"
                        android:layout_height="100dp" />
    
                    <TextView
                        android:layout_width="wrap_content"
                        android:layout_height="wrap_content"
                        android:text="正在玩命加载更多"
                        android:textSize="25sp" />
                </LinearLayout>
    
                <TextView
                    android:id="@+id/reload"
                    android:layout_width="match_parent"
                    android:layout_height="110dp"
                    android:gravity="center"
                    android:text="加载失败，请点击重新加载"
                    android:textSize="25sp" />
    
            </LinearLayout>
    
        </androidx.cardview.widget.CardView>
        
    </RelativeLayout>
    ```

    ![image-20220210001817787](image-20220210001817787.png)

    

### 3. 效果

1. 效果图

    ![image-20220210001847506](image-20220210001847506.png)

    ![image-20220210001857986](image-20220210001857986.png)

    ![image-20220210001914059](image-20220210001914059.png)
