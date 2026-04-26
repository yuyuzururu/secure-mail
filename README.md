# Secure Mail · 端到端加密安全邮件系统

> 网络安全课程设计作品 —— 一个邮件全程加密、支持数字签名和收件回执的 Web 邮件系统。

## 功能概览

- 🔐 **混合加密**：AES-256-GCM 加密邮件正文，RSA-OAEP 封装对称密钥
- ✍️ **数字签名**：RSA-PSS 签名邮件摘要，收件方可验证发件人身份与内容完整性
- 📧 **邮箱验证**：注册后发送时效确认链接，防止恶意注册
- 🧾 **收件回执**：收件方可生成签名回执，发送方可查验签收状态
- 💾 **私钥保护**：用户私钥经 PBKDF2 + AES-GCM 加密存储，仅用户密码可解密
- ⚡ **会话缓存**：登录后私钥临时缓存（10分钟有效），敏感操作支持弹窗降级
- 📱 **响应式界面**：移动端/桌面端自适应，收件人实时搜索补全

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Flask + SQLAlchemy + Flask-Login |
| 数据库 | SQLite |
| 密码学 | cryptography (RSA, AES-GCM, PBKDF2) |
| 前端 | 原生 HTML/CSS/JS，AJAX 无刷新交互 |



## 快速启动

```bash
# 1. 克隆项目
git clone https://github.com/你的用户名/secure-mail.git
cd secure-mail

# 2. 安装依赖
pip install -r requirements.txt

# 3. 初始化数据库
python setup_db.py

# 4. 运行（邮件确认链接会打印在控制台）
python run.py
