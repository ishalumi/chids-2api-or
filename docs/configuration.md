# 配置说明

## 环境变量

| 变量名 | 默认值 | 描述 |
|--------|--------|------|
| `PORT` | 3002 | 服务端口 |
| `DEBUG_ENABLED` | true | 启用调试日志 |
| `ADMIN_USER` | admin | 管理员用户名 |
| `ADMIN_PASS` | admin123 | 管理员密码 |
| `ADMIN_PATH` | /admin | 管理界面路径 |
| `GPT_MAIL_API_KEY` | gpt-test | GPTMail API Key（支持从 `gpt-mail/gpt-key.txt` 读取） |
| `GPT_MAIL_BASE_URL` | https://mail.chatgpt.org.uk | GPTMail API 基础地址 |

## 配置文件

支持 `.env` 文件加载环境变量：

```env
PORT=3002
DEBUG_ENABLED=true
ADMIN_USER=admin
ADMIN_PASS=your_password
ADMIN_PATH=/your_admin_path
GPT_MAIL_API_KEY=gpt-test
GPT_MAIL_BASE_URL=https://mail.chatgpt.org.uk
```

## 配置加载

配置通过 `internal/config/config.go` 加载，优先级：

1. 环境变量
2. `.env` 文件
3. 默认值

> 如果未设置 `GPT_MAIL_API_KEY`，会尝试读取项目内的 `gpt-mail/gpt-key.txt`。

## 安全建议

- 生产环境务必修改 `ADMIN_USER` 和 `ADMIN_PASS`
- 使用随机字符串作为 `ADMIN_PATH`
- 不要将 `.env` 文件提交到版本控制
