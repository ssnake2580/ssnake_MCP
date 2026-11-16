# SSLScan MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供SSLScan功能进行SSL/TLS安全评估。

## 功能

提供`do-sslscan`工具，允许通过MCP协议使用SSLScan检查目标服务器的SSL/TLS配置安全性，包括：

- 支持的加密套件（密码）
- 证书信息和强度
- SSL/TLS协议版本支持
- 已知SSL/TLS漏洞检测（如Heartbleed、POODLE等）
- TLS压缩、重新协商等安全功能检查

## 安装要求

- Python 3.8+
- SSLScan (已安装并可访问)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保SSLScan已安装：
```bash
# 检查sslscan是否可用
sslscan --version

# 在Linux上安装sslscan
sudo apt-get install sslscan  # Ubuntu/Debian
sudo yum install sslscan      # CentOS/RHEL

# 在macOS上安装sslscan
brew install sslscan
```

## 使用方法

### 启动服务器

```bash
python server.py <sslscan_binary>
```

例如：
```bash
# 如果sslscan在系统PATH中
python server.py sslscan

# 使用完整路径
python server.py /usr/bin/sslscan
```

### 工具函数

#### do_sslscan

执行SSLScan，这是一个全面的SSL/TLS扫描器，能识别Web服务器和其他服务的SSL/TLS配置中支持的密码套件、SSL/TLS版本、证书信息和安全漏洞。它帮助安全专业人员评估SSL/TLS实现的安全状况。

**参数：**
- `target` (str): 要扫描的目标URL（必须以https://开头以进行正确的SSL/TLS扫描）
- `sslscan_args` (List[str], 可选): 额外的SSLScan参数

**常用参数说明：**

| 参数 | 功能描述 |
|------|----------|
| `--sni-name=<name>` | SNI主机名 |
| `--ipv4, -4` | 仅使用IPv4 |
| `--ipv6, -6` | 仅使用IPv6 |
| `--show-certificate` | 显示完整证书信息 |
| `--show-certificates` | 显示完整证书链信息 |
| `--show-client-cas` | 显示TLS客户端认证的可信CA |
| `--no-check-certificate` | 不警告弱证书算法或密钥 |
| `--ocsp` | 从服务器请求OCSP响应 |
| `--ssl2` | 仅检查SSLv2是否启用 |
| `--ssl3` | 仅检查SSLv3是否启用 |
| `--tls10` | 仅检查TLSv1.0密码 |
| `--tls11` | 仅检查TLSv1.1密码 |
| `--tls12` | 仅检查TLSv1.2密码 |
| `--tls13` | 仅检查TLSv1.3密码 |
| `--tlsall` | 检查所有TLS版本密码 |
| `--no-colour` | 禁用彩色输出 |
| `--no-heartbleed` | 不检查OpenSSL Heartbleed漏洞 |
| `--no-compression` | 不检查TLS压缩（CRIME漏洞） |
| `--no-renegotiation` | 不检查TLS重新协商 |
| `--starttls-smtp` | SMTP的STARTTLS设置 |
| `--starttls-imap` | IMAP的STARTTLS设置 |
| `--starttls-pop3` | POP3的STARTTLS设置 |
| `--starttls-ftp` | FTP的STARTTLS设置 |
| `--xml=<file>` | 将结果输出到XML文件 |

**返回：** SSLScan SSL/TLS安全评估的结果

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "sslscan-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/sslscan-mcp/server.py", "sslscan"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "sslscan-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/sslscan-mcp/server.py", "sslscan"]
    }
  }
}
```

## 使用示例

### 基本SSL/TLS安全扫描
```python
# 对网站进行基本SSL/TLS扫描
target = "https://example.com"
```

### 显示详细证书信息
```python
# 显示完整的证书信息
target = "https://example.com"
sslscan_args = ["--show-certificate"]
```

### 检查特定协议版本
```python
# 仅检查TLS 1.2和TLS 1.3支持
target = "https://example.com"
sslscan_args = ["--tls12", "--tls13"]
```

### 检查不安全协议
```python
# 检查是否启用了不安全的SSL版本
target = "https://example.com"
sslscan_args = ["--ssl2", "--ssl3"]
```

### 检查特定漏洞
```python
# 完整的安全检查，包括所有漏洞
target = "https://example.com"
sslscan_args = ["--show-certificate", "--tlsall"]
```

### 扫描非标准服务
```python
# 扫描使用STARTTLS的SMTP服务器
target = "example.com:25"
sslscan_args = ["--starttls-smtp"]

# 扫描使用STARTTLS的IMAP服务器
target = "mail.example.com:143"
sslscan_args = ["--starttls-imap"]
```

### 将结果导出到XML
```python
# 将扫描结果保存为XML格式
target = "https://example.com"
sslscan_args = ["--xml=results.xml"]
```

## 输出示例

SSLScan的典型输出包含以下信息：

```
Version: 2.0.10-static
OpenSSL 1.1.1n  15 Mar 2022

Connected to example.com

Testing SSL server example.com on port 443 using SNI name example.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.2 not vulnerable to heartbleed
TLSv1.3 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384       Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256       Curve 25519 DHE 253
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253

  Server Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  example.com
Issuer:   DigiCert TLS RSA SHA256 2020 CA1

Not valid before: Dec  8 00:00:00 2020 GMT
Not valid after:  Dec  7 23:59:59 2021 GMT
```

## 安全结果分析

### 安全配置的特征
- **只启用TLS 1.2和TLS 1.3**：禁用旧版协议（SSLv2、SSLv3、TLS 1.0、TLS 1.1）
- **强密码套件**：首选AEAD加密（GCM、CHACHA20-POLY1305）
- **强密钥交换**：使用ECDHE（Elliptic Curve Diffie-Hellman Ephemeral）
- **现代曲线**：如Curve 25519
- **证书使用强签名算法**：SHA256或更高
- **合适的密钥长度**：RSA至少2048位
- **不支持已知漏洞**：如Heartbleed、CRIME等

### 不安全配置的警告标志
- 支持SSLv2或SSLv3
- 支持弱密码（如RC4、DES、3DES）
- 使用MD5或SHA1签名算法
- 证书已过期或自签名
- 使用小于2048位的RSA密钥
- 启用了TLS压缩（可能导致CRIME攻击）
- 不安全的TLS重新协商

## 常见问题

### Q: 扫描结果显示弱密码支持
A: 配置服务器仅使用强密码套件，禁用弱加密算法

### Q: 发现过时的SSL/TLS版本
A: 在服务器配置中禁用SSLv2、SSLv3、TLS 1.0和TLS 1.1

### Q: 证书警告
A: 确保证书由可信CA签发，使用强签名算法，并且未过期

### Q: 无法连接到服务器
A: 检查URL格式、防火墙设置，以及服务器是否运行

## 安全警告

此工具仅用于合法的网络安全测试和管理目的。请确保：
- 只在您拥有或有明确授权的系统上进行扫描
- 遵守所有适用的法律法规
- 谨慎解释结果，避免误报
- 与利益相关者分享发现的安全问题
- 建议实施安全最佳实践

## 许可证

本项目基于MIT许可证发布。 