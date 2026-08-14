## Chat room

借助 Cloudflare 托管的在线聊天室，支持 $\LaTeX$ 和 markdown。

可通过 admin(root) 的 GUI 界面创建/删除用户、管理全员权限。

拥有相关指令的管理员可以通过 `/指令` 的方式管理成员。

支持聊天室 BOT，借助 Cloudflare 加密储存您的 API KEY。

更多指令可通过 `/help` 进行查看。

### Quick Start
#### 1. 环境准备
确保你已安装 [Node.js (v16+)](https://nodejs.org/?spm=a2ty_o01.29997173.0.0.47e355fbf3zPjw) 并拥有 [Cloudflare](https://dash.Cloudflare.com/sign-up?spm=a2ty_o01.29997173.0.0.47e355fbf3zPjw) 账号。

```bash
# 克隆项目
git clone https://github.com/ggenerals/chat.git
cd chat

# 安装 Wrangler CLI
npm install
```

#### 2. 配置环境变量 (AI API Key)
如果不需要 AI BOT 可以跳过这一步，并且建议取消所有人的 AI 使用权限。

```bash
# 登录 Cloudflare (如果尚未登录)
npx wrangler login

# 设 DeepSeek API Key (按提示输入 Key)
npx wrangler secret put AI_API_KEY
```

#### 3. 本地开发运行
启动本地开发服务器。

```bash
npm run dev
# 或者
npx wrangler dev
```

#### 4. 部署到 Cloudflare
部署到 Cloudflare。

```bash
npx wrangler deploy
```


### 更多
admin(超级管理员) 默认密码为 `123456`

正在开发，欢迎提交 Issue。