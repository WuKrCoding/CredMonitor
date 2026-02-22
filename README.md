# CredMonitor - 证书过期监控系统

一个基于 Flask 的 SSL/TLS 证书过期时间监控系统，支持多域名证书状态实时检查和预警。

## 功能特性

- 🔍 **实时证书检查**：支持 DNS、IP、CNAME 多种连接方式
- 📊 **可视化仪表板**：直观展示证书状态、剩余天数和到期时间
- ⚠️ **智能预警**：根据剩余天数自动分级（正常/即将过期/已过期）
- 🔑 **权限管理**：管理员可管理域名，普通用户只读
- 🎨 **拖拽排序**：支持自定义域名展示顺序
- 🐳 **Docker 部署**：开箱即用的容器化部署方案

## 快速开始

### Docker Compose 部署（推荐）

1. 克隆项目：
```bash
git clone <repository-url>
cd CredMonitor
```

2. 配置环境变量（可选）：
```bash
cp .env.example .env
# 编辑 .env 文件自定义配置
```

3. 启动服务：
```bash
docker-compose up -d
```

4. 访问应用：
```
http://localhost:5000
```

### 本地开发部署

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 初始化数据库并启动：
```bash
python app.py
```

3. 访问应用：
```
http://localhost:5000
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DATABASE_PATH` | `credmonitor.db` | 数据库文件路径 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `PORT` | `5000` | 监听端口 |
| `DEBUG` | `False` | 调试模式 |

## 用户管理

### 首次使用

1. 访问 `/register` 注册第一个账号
2. 第一个注册的用户自动成为**管理员**
3. 注册功能在此后自动关闭

### 管理员功能

- ✅ 添加/删除域名
- ✅ 拖拽排序域名
- ✅ 添加新用户（通过 API）

### 普通用户功能

- 👁️ 查看所有域名状态
- 🚫 无法修改域名配置

## API 接口

### 域名管理

- `GET /api/domains` - 获取所有域名
- `POST /api/domains` - 添加域名（管理员）
- `DELETE /api/domains/<id>` - 删除域名（管理员）
- `POST /api/domains/reorder` - 更新域名排序（管理员）

### 用户管理

- `POST /api/users` - 添加用户（管理员）

### 证书检查

- `POST /api/domains/check-all` - 检查所有域名证书状态

## 系统要求

- Python 3.11+
- Docker & Docker Compose（容器部署）
- 网络访问权限（用于证书检查）

## 技术栈

- **后端**：Flask
- **数据库**：SQLite
- **前端**：原生 JavaScript + CSS
- **证书检查**：cryptography + dnspython
- **部署**：Docker

## 项目结构

```
CredMonitor/
├── app.py                 # Flask 应用主程序
├── requirements.txt        # Python 依赖
├── Dockerfile            # Docker 镜像构建
├── docker-compose.yml    # Docker Compose 配置
├── .env.example          # 环境变量示例
├── templates/
│   └── index.html       # 前端页面
└── data/                # 数据持久化目录
```

## 许可证

MIT License
