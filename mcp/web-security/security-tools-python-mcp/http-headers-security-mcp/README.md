# HTTP头部安全分析MCP服务器

本项目是一个用于HTTP头部安全分析的FastMCP服务器。它可以帮助用户识别网站响应中可能存在的安全风险，包括可能泄露敏感信息的HTTP头部以及缺少的安全推荐头部。

## 功能特点

- 分析HTTP响应头部，识别潜在安全风险
- 检测应该移除的不安全头部（基于OWASP安全最佳实践）
- 检测缺少的推荐安全头部
- 提供详细的安全建议

## 安装

### 前提条件

- Python 3.7+
- FastMCP库

### 安装步骤

1. 克隆仓库
2. 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
python server.py
```

### API接口

#### analyze-http-header

分析HTTP响应头部的安全性，检查是否存在不安全的头部以及是否缺少推荐的安全头部。

**参数:**

- `target`: 目标URL，用于分析其HTTP响应头部安全性，例如 https://example.com

**返回:**

JSON格式的分析结果，包含两部分：

- `removeHeaders`: 应该移除的不安全HTTP头部列表
- `addedHeaders`: 应该添加的安全HTTP头部列表及其建议值

**示例:**

```json
{
  "removeHeaders": [
    "Server: nginx/1.18.0",
    "X-Powered-By: PHP/7.4.3"
  ],
  "addedHeaders": [
    "Content-Security-Policy: default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
    "X-Content-Type-Options: nosniff"
  ]
}
```

## 安全头部说明

### 应该移除的HTTP头部

这些HTTP头部可能会泄露服务器或应用的敏感信息，建议在生产环境中移除：

- `Server`: 暴露Web服务器类型和版本
- `X-Powered-By`: 暴露服务器端编程语言或框架
- `X-AspNet-Version`: 暴露ASP.NET版本
- 其他可能泄露技术栈信息的头部

### 推荐添加的安全HTTP头部

这些HTTP头部可以提高Web应用的安全性：

- `Content-Security-Policy`: 减少XSS攻击风险
- `X-Content-Type-Options`: 防止MIME类型嗅探
- `X-Frame-Options`: 防止点击劫持
- `Strict-Transport-Security`: 强制使用HTTPS连接
- 其他符合OWASP安全最佳实践的头部

## 配置文件

- `owasp_headers_remove.json`: 包含应该移除的不安全HTTP头部列表
- `owasp_headers_add.json`: 包含应该添加的安全HTTP头部列表及其推荐值

## 许可证

[MIT](LICENSE)

## 参考资料

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) 