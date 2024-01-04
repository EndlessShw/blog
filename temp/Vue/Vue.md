# Vue3

## 1. 后台管理系统整理

### 1. 准备工作

#### 1. 创建项目

1. 使用 Create Preset 创建项目

2. 在 tsconfig.json 和 vite.config.ts 中导入项目别名

3. 使用：
    ```bash
    pnpm install
    ```

    来引入项目所需要的依赖。

#### 2. 配置路由

1. 在 router/index.ts 中配置路由，注意子路由：
    ```ts
    const routes: Array<RouteRecordRaw> = [
      {
        path: '/',
        name: 'home',
        component: () => import('@views/home.vue'),
        // 配置子路由
        children: [
          {
            path: '',
            name: 'index',
            component: () => import('@views/index.vue'),
          },
          {
            path: 'userinfo',
            name: 'userInfo',
            component: () => import('@views/user-info.vue'),
          },
          {
            path: 'fundlist',
            name: 'fundList',
            component: () => import('@views/fund-list.vue'),
          },
        ],
      },
      // 配置 404 页面
      {
        path: '/:catchAll(.*)*',
        name: '404',
        component: () => import('@/views/404.vue'),
      },
      // 配置注册界面
      {
        path: '/register',
        name: 'register',
        component: () => import('@/views/register.vue'),
      },
      // 配置登录路由
      {
        path: '/login',
        name: 'login',
        component: () => import('@/views/login.vue'),
      },
    ]
    ```

2. 是否登录的判断（路由守卫）：
    ```ts
    router.beforeEach((to) => {
      const isLogin: Boolean = localStorage.token ? true : false
      if (isLogin && to.name === 'login') {
        return '/'
      }
      if (!isLogin && to.name === 'home') {
        return '/login'
      }
    })
    ```

#### 3. 引入依赖和插件

1. 如果需要某个依赖和插件，现在项目根目录下运行：
    ```bash
    pnpm install 具体依赖和插件名
    ```

    详细使用可以见官网

2. 在全局的 main.ts 中引入和挂载
    ```ts
    import { createApp } from 'vue'
    import { createPinia } from 'pinia'
    import App from '@/App.vue'
    import router from '@/router'
    import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'
    import * as ElementPlusIconsVue from '@element-plus/icons-vue'
    // 不用全局导入，改用按需导入
    // import ElementPlus from 'element-plus'
    // import 'element-plus/dist/index.css'
    
    // 全局样式
    import '@/styles/var.less'
    import '@/styles/mixin.less'
    import '@/styles/global.less'
    
    // 如果导入的东西需要组件，那就要单独拿出来，再链式 use()
    const pinia = createPinia()
    pinia.use(piniaPluginPersistedstate)
    
    const app = createApp(App)
    // 全局导入 Icon（自动导入有问题）
    for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
      app.component(key, component)
    }
    app
      .use(pinia)
      // 挂载路由
      .use(router)
      // .use(ElementPlus)    全局导入
      .mount('#app')
    ```

    如果官方有说明，也可以使用官方的使用说明来进行自动导入。插件要在 vite.config.ts 中配置。

### 2. 全局路由渲染

1. App.vue 为顶级路由，如果没有特殊要求，就用：`<router-view />` 来渲染一级路由即可。

2. 如果使用 ElementUIPlus 并配置中文环境，还需要：
    ```vue
    <template>
      <el-config-provider :locale="zhCn">
        <router-view />
      </el-config-provider>
    </template>
    ```

### 3. 注册界面设计的知识点

#### 1. axios 的使用

1. 添加拦截器（utils/http.ts)：
    ```ts
    import { useRouter } from 'vue-router'
    const router = useRouter()
    // 封装 axios
    import axios from 'axios'
    
    // 请求拦截，在发送请求前进行操作
    axios.interceptors.request.use(
      (config) => {
        // 如果当前浏览器有 token，说明已经通过了身份验证，此时头部需要添加 Authorization 来添加 token
        if (localStorage.token) {
          config.headers.Authorization = localStorage.token
        }
        return config
      },
      // 请求错误时做些什么
      (error) => {
        return Promise.reject(error)
      }
    )
    
    // 响应拦截，在得到响应后，对响应体的处理
    axios.interceptors.response.use(
      (response) => {
        return response
      },
      // 超出 2xx 范围的状态码要做的事情
      (error) => {
        // 通过解构来获取响应体的相关内容
        const { status } = error.response
        // 如果访问页面时提示未授权，那么表示当前 token 过期或者被伪造
        // 此时需要清空 token 并让其重新登录
        if (status === 401 && error.response.data === 'Unauthorized') {
          localStorage.removeItem('token')
          router.push({
            name: 'login',
          })
        }
        return Promise.reject(error)
      }
    )
    
    export default axios
    ```

2. 设计到跨域请求，因此还要配置代理(vite.config.ts)：
    ```ts
    /**
     * 本地开发服务，也可以配置接口代理
     * @see https://cn.vitejs.dev/config/#server-proxy
     */
    server: {
      port: 3000,
      proxy: {
        // 这里要配置反向代理以解决跨域问题
        '/api': {
          target: 'https://www.thenewstep.cn/backend/8007',
          changeOrigin: true,
          // 正确的接口路径里面是没有 /api 的，所以就需要 pathRewrite
          // 用 ^/api: '' 把 /api 去掉，这样既能有正确的标识，又能在请求接口的时候去掉 /api
          // rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
    ```

3. 一个 axios 请求：
    ```ts
    formEl.validate(async (valid) => {
      // 如果校验成功
      if (valid) {
        // 通过 axios 发出请求
        await axios
          .post('/api/users/register', registerUser.value)
          // 处理成功请求
          .then(() => {
            // 输出注册成功的提示
            // 因为开启了自动化导入，如果再手动导入的话，就会发生冲突，从而导致
            // @ts-ignore
            // eslint-disable-next-line no-undef
            ElMessage({
              message: '恭喜！注册成功！',
              type: 'success',
            })
            // 跳转回登录
            router.push({
              // 注意这里是 name，填的是路由的名字，而不是路由地址
              name: 'login',
            })
          })
          // 统一处理非 2xx 的失败请求
          // @ts-ignore
          // eslint-disable-next-line no-undef
          .catch(function (error) {
            if (error.response.status === 400) {
              // @ts-ignore
              // eslint-disable-next-line no-undef
              ElMessage.error(error.response.data.msg)
            } else {
              // @ts-ignore
              // eslint-disable-next-line no-undef
              ElMessage.error('发生未知错误！注册失败！')
            }
          })
      } else {
        // 格式不正确时点击注册的结果
        console.log('注册失败！')
        // @ts-ignore
        // eslint-disable-next-line no-undef
        ElMessage.error('注册失败！')
        return false
      }
    })
    ```

4. 数据校验规则可参照 ElementUI 官方文档编写

### 4. 登录界面涉及的知识点

#### 1. 获取 token 并解析

1. 使用 jwt 工具对其进行解析，需要 pnpm 引入：
    ```ts
    // 获取 token 并将其存储到 localStorage 中，以便路由守卫使用
    localStorage.setItem('token', response.data.token)
    // 解析 token
    const decodedToken: userInfoType = jwt_decode(response.data.token)
    console.log(decodedToken)
    // !! 等价于 Boolean()
    // 将 token 解析后的数据存放在 pinia 的全局状态中
    authStore.setAuth(!!decodedToken)
    authStore.setUser(decodedToken)
    ```

#### 2. 使用 pinia 进行全局状态管理

1. 创建 stores/index.ts，在其中配置 pinia：
    ```ts
    import { defineStore } from 'pinia'
    import { userInfoType } from '@utils/types'
    export const useAuthStore = defineStore('auth', {
      state: () => ({
        // 是否是已授权状态
        isAuthenticated: false,
        // 存储用户的信息
        userInfo: {},
      }),
      getters: {
        getAuthenticated: (state) => state.isAuthenticated,
        getUserInfo: (state) => state.userInfo,
      },
      actions: {
        /**
         * 设置 state 的 isAuthenticated，相当于 setter
         * @param isAuth 外部传入的是否登录状态
         */
        setAuth(isAuth: boolean) {
          this.isAuthenticated = isAuth
        },
        setUser(userInfo: userInfoType | null) {
          if (userInfo) {
            this.userInfo = userInfo
          } else {
            this.userInfo = {}
          }
        },
      },
      // 调用持久化插件，让 useAuthStore 持久化
      // 之后直接导包取出使用即可，不需要再从 localStorage 中取出了
      persist: true,
    })
    ```

2. 配置 pinia 后，token 等信息就可以放置在全局，建议配置持久化，否则一刷新就会消失，当然手动存放在 localStorage 也可以：

    ```ts
    // 建议使用 pinia 持久化插件来实现
    // 这里通过使用 localStorage 来持久化存储 pinia 简单的全局状态数据
    import { watchEffect } from 'vue'
    import jwt_decode from 'jwt-decode'
    import { useAuthStore } from '@stores/index'
    const authStore = useAuthStore()
    /**
     * 调用监听函数，每次刷新页面的时候（由于会自动加载 App.vue），从 localStorage 中取出全局数据
     * 因为 pinia 的全局对象在刷新后会丢失（存在内存中），因此每次刷新后都要重新获取。
     */
    watchEffect(() => {
      if (localStorage.token) {
        const decodeToken = jwt_decode(localStorage.token)
        authStore.setAuth(!!decodeToken)
        authStore.setUser(decodeToken)
      }
    })
    ```

### 5. 布局导航涉及的知识点

1. 没啥知识点，贴代码(components/navbar.vue)：
    ```vue
    <template>
      <nav class="nav">
        <el-row>
          <el-col :span="12" class="logo-container">
            <img src="@img/logo.png" class="logo" alt="logo" />
            <span class="title">后台管理系统</span>
          </el-col>
          <el-col :span="12" class="user">
            <div class="user-info">
              <img v-if="avatar" :src="avatar" class="avatar" alt="user" />
              <img v-else src="@img/logo.png" class="avatar" alt="user" />
              <div class="welcome-content">
                <p class="content welcome">欢迎</p>
                <p class="content username">{{ name }}</p>
              </div>
              <span class="el-dropdown">
                <!-- ElementUI Plus 中，使用 command 对下拉的不同选项进行处理，详见文档 -->
                <!-- trigger 属性表示点击的时候触发 -->
                <el-dropdown
                  trigger="click"
                  class="dropdown"
                  @command="handleDropdown"
                >
                  <span class="el-dropdown-link">
                    <el-icon><ArrowDown /></el-icon>
                  </span>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="info">个人信息</el-dropdown-item>
                      <el-dropdown-item command="logout">注销</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
              </span>
            </div>
          </el-col>
        </el-row>
      </nav>
    </template>
    
    <script setup lang="ts">
    import router from '@/router'
    import { useAuthStore } from '@stores/index'
    import { toRef } from 'vue'
    
    const authStore = useAuthStore()
    // 将 authStore 中的 userInfo 对象解构出来，为 ref 类型
    // 指定 any 是为了使其能够读取属性
    const userInfo: any = toRef(authStore, 'userInfo')
    const { name } = userInfo.value
    const { avatar } = userInfo.value
    
    const handleDropdown = (command: string) => {
      switch (command) {
        case 'info':
          info()
          break
        case 'logout':
          logout()
          break
      }
    }
    
    const info = () => {
      router.push({
        name: 'userInfo',
      })
    }
    
    const logout = () => {
      console.log('退出登录！')
      authStore.setAuth(false)
      authStore.setUser(null)
      localStorage.removeItem('token')
      router.push({
        name: 'login',
      })
    }
    </script>
    
    <style scoped>
    .nav {
      width: 100%;
      height: 60px;
      min-width: 600px;
      padding: 5px;
      background: #074c62;
      color: #fff;
      border-bottom: 1px solid #1f2d3d;
    }
    .logo-container {
      line-height: 60px;
      min-width: 400px;
    }
    
    .logo {
      height: 50px;
      width: 50px;
      margin-right: 5px;
      vertical-align: middle;
      display: inline-block;
    }
    
    .title {
      vertical-align: middle;
      font-size: 22px;
      font-family: 'Microsoft YaHei';
      letter-spacing: 3px;
    }
    
    .user-info {
      line-height: 60px;
      text-align: right;
      padding-right: 10px;
    }
    
    .avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      vertical-align: middle;
      display: inline-block;
    }
    
    .content {
      line-height: 20px;
      text-align: center;
      font-size: 14px;
    }
    
    .welcome {
      font-size: 12px;
    }
    
    .welcome-content {
      display: inline-block;
      width: auto;
      vertical-align: middle;
      padding: 0 5px;
    }
    
    .username {
      color: #409eff;
      font-weight: bolder;
    }
    
    .dropdown {
      cursor: pointer;
      margin-right: 5px;
    }
    
    .el-dropdown {
      color: #fff;
    }
    
    .dropdown {
      margin-top: 25px;
    }
    </style>
    ```

2. 注意一下子组件的挂载（views/home.vue)：
    ```vue
    <template>
      <div class="home">
        <!-- 挂载子组件 -->
        <navbar />
        <!-- 渲染子路由 -->
        <!-- 这里将侧边栏让出来，也就是侧边栏不覆盖主页位置 -->
        <div class="container-right">
          <RouterView />
        </div>
        <sidebar />
      </div>
    </template>
    
    <script setup lang="ts">
    import { onMounted } from 'vue'
    import axios from '@utils/http'
    // setup 语法糖，直接挂载子组件
    import navbar from '@cp/navbar.vue'
    import sidebar from '@cp/sidebar.vue'
    
    // 在 setup() 中执行，生命周期函数，在组件挂载完成后通过 axios 发出请求
    onMounted(async () => {
      try {
        const data = await axios.get(
          '/api/users/current'
          // 这里的请求头要添加的参数直接通过请求拦截来添加
          // {
          // // 定义请求头参数
          // headers: {
          //   // 指定 Authorization 的值为 token
          //   Authorization: localStorage.getItem('token'),
          // },
          // }
        )
        console.log(data)
      } catch (error) {
        console.log(error)
      }
    })
    </script>
    
    <style lang="less" scoped>
    .home {
      width: 100%;
      height: 100%;
      overflow: hidden;
    }
    
    .container-right {
      position: relative;
      top: 0;
      left: 180px;
      width: calc(100% - 180px);
      height: calc(100% - 71px);
      overflow: auto;
    }
    </style>
    ```

### 6. 侧边栏的编写

#### 1. 根据数据动态生成侧边栏的内容

1. 涉及到 vue 原生指令的一些知识点，需要注意：
    ```vue
    <template>
      <!-- 写侧边栏 -->
      <el-row class="menu-container">
        <el-col :span="12">
          <el-menu
            default-active="home"
            class="menu-vertical"
            active-text-color="#ffd04b"
            background-color="#074c62"
            text-color="#fff"
          >
            <router-link :to="{ name: 'home' }">
              <el-menu-item index="home">
                <template #title>
                  <el-icon>
                    <HomeFilled />
                  </el-icon>
                  <span>首页</span>
                </template>
              </el-menu-item>
            </router-link>
            <!-- 改用动态创建侧边栏 -->
            <!-- 遍历 menus ref -->
            <!-- 用 :key 来强制排序顺序 -->
            <template v-for="menu in menus" :key="menu.path">
              <!-- 如果其子元素有 children -->
              <!-- element-plus 的 index 未必一定为数字，而且这里可有可无 -->
              <el-sub-menu v-if="menu.children" :index="menu.path">
                <template #title>
                  <el-icon>
                    <!-- :is 用于绑定动态组件 -->
                    <component :is="menu.icon" />
                  </el-icon>
                  <span>{{ menu.name }}</span>
                </template>
                <router-link
                  v-for="(item, index) in menu.children"
                  :key="index"
                  :to="{ name: item.path }"
                >
                  <el-menu-item :index="item.path">
                    {{ item.name }}
                  </el-menu-item>
                </router-link>
              </el-sub-menu>
            </template>
            <!-- <el-sub-menu index="2">
              <template #title>
                <el-icon>
                  <Money />
                </el-icon>
                <span>资金管理</span>
              </template>
              <el-menu-item index="2-1">资金流水</el-menu-item>
            </el-sub-menu> -->
            <!-- <el-sub-menu index="3">
              <template #title>
                <el-icon>
                  <InfoFilled />
                </el-icon>
                <span>信息管理</span>
              </template>
              <el-menu-item index="3-1">个人信息</el-menu-item>
            </el-sub-menu> -->
          </el-menu>
        </el-col>
      </el-row>
    </template>
    
    <script setup lang="ts">
    // import { HomeFilled, Money, InfoFilled } from '@element-plus/icons-vue'
    import { ref } from 'vue'
    // 动态获取侧边栏，让其更加通用
    // 这里模拟动态数据，实际业务中这些数据要动态获取
    const menus = ref([
      {
        icon: 'Money',
        name: '资金管理',
        // 跳转的路径
        path: 'fund',
        children: [
          {
            path: 'fundList',
            name: '资金流水',
          },
        ],
      },
      {
        icon: 'InfoFilled',
        name: '信息管理',
        // 跳转的路径
        path: 'info',
        children: [
          {
            path: 'userInfo',
            name: '个人信息',
          },
        ],
      },
    ])
    </script>
    
    <style scoped>
    .menu-container {
      position: fixed;
      top: 71px;
      left: 0;
      min-height: 100%;
      background-color: #074c62;
      z-index: 99;
    }
    
    .el-menu {
      border: none;
    }
    
    .fa-margin {
      margin-right: 5px;
    }
    
    .menu-vertical:not(.el-menu--collapse) {
      width: 180px;
      min-height: 100vh;
    }
    
    .menu-vertical {
      width: 35px;
    }
    
    .el-sub-menu .el-menu-item {
      min-width: 180px;
      /* 使用一个 !important 规则时，此声明将覆盖任何其他声明。不好的习惯 */
      padding-left: 50px !important;
    }
    
    .hiddenDropdown,
    .hiddenDropname {
      display: none;
    }
    
    a {
      text-decoration: none;
    }
    </style>
    ```

### 7. 表格的编写

1. 涉及到父子组件通过 props/emits 通信

2. 涉及到 vue 的 `ref` 

3. 代码：
    ```vue
    <template>
      <!-- 注意这里不能用 v-model，因为新版本对 v-model 有要求 -->
      <el-dialog
        :modelValue="show"
        :before-close="handleClose"
        :title="myDialogType + '收支信息'"
      >
        <!-- ref 属性类似原生的 id 属性，用于挂载 DOM 节点和在 ts 中获取节点（代替原生的 querySelector -->
        <el-form
          :model="formData"
          ref="formRef"
          :rules="formRules"
          label-width="120px"
          style="margin: 10px; width: auto"
        >
          <el-form-item label="收支类型">
            <el-select v-model="formData.type" placeholder="收支类型">
              <el-option
                v-for="(type, index) in typeList"
                :key="index"
                :label="type"
                :value="type"
              ></el-option>
            </el-select>
          </el-form-item>
          <!-- prop 为 model 的键名。 在定义了 validate、resetFields 的方法时，该属性是必填的 -->
          <el-form-item prop="describle" label="收支描述">
            <el-input v-model="formData.describe" type="describe" /> </el-form-item
          ><el-form-item prop="income" label="收入">
            <el-input v-model="formData.income" type="imcome" />
          </el-form-item>
          <el-form-item prop="expend" label="支出">
            <el-input v-model="formData.expend" type="expend" />
          </el-form-item>
          <el-form-item prop="cash" label="账户现金">
            <el-input v-model="formData.cash" type="cash" />
          </el-form-item>
          <el-form-item label="备注">
            <el-input v-model="formData.remark" type="textarea" />
          </el-form-item>
          <el-form-item class="text-right">
            <el-button @click="handleClose">取消</el-button>
            <el-button type="primary" @click="handleSubmit(formRef)"
              >提交</el-button
            >
          </el-form-item>
        </el-form>
      </el-dialog>
    </template>
    
    <script setup lang="ts">
    import { FormInstance, FormRules } from 'element-plus'
    import { reactive, ref, watch } from 'vue'
    import axios from '@utils/http'
    import { formDataType } from '@utils/types'
    // 动态生成支付类型
    const typeList = ref(['现金', '微信', '支付宝', '银行卡'])
    // 接收表单提交的数据
    const formData = ref<formDataType>({
      type: '现金',
      describe: '购买课程',
      income: '1580',
      expend: '158',
      cash: '2000',
      remark: '收收米',
    })
    // 定义 form 表单节点，节点的类型就是 FormInstance 类型。
    // 这也就是为什么 <el-form> 有 ref 属性
    const formRef = ref<FormInstance>()
    
    /**
     * 处理提交按钮事件
     * @param formEl 传入的 ref 的 DOM 节点，这里就是 FormInstance 类型的 Form 节点
     */
    const handleSubmit = (formEl: FormInstance | undefined) => {
      if (!formEl) return
      formEl.validate(async (valid: boolean) => {
        // 如果校验成功
        if (valid) {
          const url = ref<string>()
          switch (props.myDialogType) {
            case '添加':
              url.value = 'add'
              break
            case '编辑':
              url.value = `edit/${props.editData?._id}`
              break
          }
          await axios.post(`/api/profiles/${url.value}`, formData.value)
          // eslint-disable-next-line no-undef
          ElMessage.success(`${props.myDialogType}成功!`)
          // 请求父组件再一次发送请求
          emits('handleUpdateProfiles')
          emits('closeDialog')
        } else {
        }
      })
    }
    
    // 定义表单的校验规则
    const formRules = reactive<FormRules>({
      describe: [{ required: true, message: '收支描述不能为空', trigger: 'blur' }],
      income: [{ required: true, message: '收入不能为空', trigger: 'blur' }],
      expend: [{ required: true, message: '支出描述不能为空', trigger: 'blur' }],
      cash: [{ required: true, message: '金额不能为空', trigger: 'blur' }],
    })
    
    // 获取 emits
    const emits = defineEmits([
      // 关闭 dialog
      'closeDialog',
      // 向父组件请求重新更新页面
      'handleUpdateProfiles',
    ])
    
    // 处理弹窗关闭后，再次点击弹窗按钮能打开弹窗
    // 这里需要用到父子组件的通信。因为弹窗是否打开取决于父组件传入子组件的 <el-dialog> 的 :modelValue=true 或者 false 来决定
    // 由于 show 是父组件传来的 props，不可修改，因此只能通过调用父组件的关闭函数
    const handleClose = () => {
      emits('closeDialog')
    }
    
    const props = defineProps({
      show: Boolean,
      // 注意这里要用 as + getter
      editData: Object as () => formDataType,
      // 设置弹窗的类型
      myDialogType: String,
    })
    
    // 监听父组件传来的一行的数据
    watch(
      () => props.editData,
      () => {
        formData.value = <formDataType>props.editData
      }
    )
    </script>
    <style scoped></style>
    
    ```

    

















