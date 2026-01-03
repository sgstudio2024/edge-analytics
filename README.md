# CDN Analytics Dashboard

🌐 多账户、多平台的 CDN 流量分析仪表盘，支持 Cloudflare 和腾讯云 EdgeOne

**原项目地址**: https://github.com/Geekertao/cloudflare-analytics
**当前项目作者**: LingMowen

## ✨ 功能特性

- 🔐 **安全登录** - 后台登录保护，密码加密存储
- 🛡️ **路径隐藏** - 后台路径自动生成，安装后自动删除安装页面
- 🌐 支持 Cloudflare 和腾讯云 EdgeOne
- 📊 多账户、多 Zone 流量监控
- 📈 实时数据图表展示
- 📅 历史数据分析（支持 1 天、3 天、7 天、30 天）
- 🎯 数据精度智能切换
- 🌍 多语言支持（中文/英文）
- 🗺️ 地理位置统计
- 💾 缓存分析和性能监控
- 📱 响应式设计

## 🚀 快速开始

### 环境要求

- Node.js 18.x 或更高版本
- npm 或 yarn

### 安装步骤

```bash
# 1. 安装依赖
npm install

# 2. 启动服务器
npm start
```

### 首次访问

1. 打开 http://your-server:4000
2. 自动跳转到安装页面
3. 完成安装向导：
   - 填写网站信息（可选）
   - 设置后台账户（必填）
   - 确认配置并完成安装
4. 牢记系统生成的后台登录路径

### 访问地址

| 页面 | 地址 | 说明 |
|------|------|------|
| 首页 | http://your-server:4000 | 流量分析仪表盘 |
| 后台登录 | http://your-server:4000/[随机路径] | 管理后台登录 |
| API | http://your-server:4000/api/* | 数据接口 |

## 📁 文件结构

```
├── admin/                  # 管理后台
│   ├── index.html          # 后台管理页面
│   ├── install.html        # 安装向导（安装后自动删除）
│   └── login.html          # 后台登录页面
├── data/                   # 数据存储
│   └── analytics.json      # 分析数据缓存
├── static/                 # 前端静态资源
│   ├── css/                # 样式文件
│   └── js/                 # JavaScript 文件
├── index.html              # 前端首页
├── index.js                # 后端主文件
├── main.js                 # 启动脚本
├── package.json            # 依赖配置
├── package-lock.json       # 依赖锁文件
├── config.json             # 应用配置
├── zones.yml               # Cloudflare 区域配置
├── favicon.svg             # 网站图标
├── site.webmanifest        # PWA 清单
└── README.md               # 说明文档
```

## ⚙️ 配置说明

### Cloudflare API Token 配置

在 `zones.yml` 文件中配置：

```yaml
accounts:
  - name: "账户名称"
    token: "你的Cloudflare API Token"
    zones:
      - domain: "example.com"
        zone_id: "你的Zone ID"
```

或使用环境变量：

```bash
export CF_TOKENS="your_token"
export CF_ZONES="zone_id"
export CF_DOMAINS="example.com"
export CF_ACCOUNT_NAME="我的账户"
```

### 端口配置

```bash
export PORT=8080  # 修改端口号，默认 4000
```

## 🔒 安全特性

### 密码安全

- 使用 PBKDF2 + SHA512 算法加密
- 100,000 次迭代
- 随机盐值保护

### 后台路径

- 安装时自动生成随机路径（如 `/a1b2c3d4`）
- 安装完成后自动删除安装页面
- 路径存储在配置文件中

### 令牌验证

- 登录成功后生成一次性令牌
- 令牌 1 小时自动过期
- 所有 API 调用需要令牌验证

## 📊 数据更新

- **更新频率**: 每小时自动更新
- **数据精度**:
  - 1 天和 3 天数据：小时级精度
  - 7 天和 30 天数据：天级精度
- **存储位置**: `data/analytics.json`

## 🛠️ 技术栈

- **前端**: React + Recharts
- **后端**: Node.js + Express
- **安全**: multer, crypto
- **部署**: 支持直接部署到网站根目录

## 🌐 支持的环境

- Linux (Ubuntu, CentOS, Debian 等)
- macOS
- Windows
- Docker

## 📝 使用说明

### 添加新的账户和 Zone

编辑 `zones.yml` 文件，添加新的账户和 Zone 配置，然后重启服务。

### 查看日志

```bash
# 开发模式查看实时日志
npm run dev
```

### 数据备份

定期备份 `data/analytics.json` 文件，防止数据丢失。

## ❓ 常见问题

### Q: 安装完成后如何访问后台？
A: 安装成功后会显示后台登录路径，请妥善保存。路径格式为 `/随机字符`。

### Q: 忘记了后台路径怎么办？
A: 查看 `config.json` 文件中的 `adminPath` 字段。

### Q: 如何修改后台密码？
A: 需要手动编辑 `config.json` 文件中的 `admin` 字段。

### Q: 端口被占用怎么办？
A: 使用环境变量 `PORT` 指定其他端口，或修改 `config.json` 中的 `PORT` 设置。

## 📄 许可证

MIT License

## 🙏 感谢

- [原项目](https://github.com/Geekertao/cloudflare-analytics) - Cloudflare Analytics Dashboard
- [React](https://reactjs.org/) - 前端框架
- [Recharts](https://recharts.org/) - 图表库
- [Express](https://expressjs.com/) - 后端框架