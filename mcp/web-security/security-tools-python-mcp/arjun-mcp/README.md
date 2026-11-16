# Arjun MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Arjun功能进行HTTP参数发现。

## 功能

提供`do-arjun`工具，允许通过MCP协议使用Arjun发现Web应用中隐藏的HTTP参数，支持多种HTTP方法和自定义配置。

## 安装要求

- Python 3.8+
- Arjun (已安装并可访问)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Arjun已安装：
```bash
# 通过pip安装
pip install arjun

# 或者从GitHub克隆
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
python server.py <arjun_binary>
```

例如：
```bash
# 直接使用arjun命令
python server.py arjun

# 如果是Python模块
python server.py "python3 -m arjun"

# 使用完整路径
python server.py /usr/local/bin/arjun
```

### 工具函数

#### do_arjun

运行Arjun发现隐藏的HTTP参数。

**参数：**
- `url` (str, 可选): 要扫描隐藏参数的目标URL
- `textFile` (str, 可选): 包含多个URL的文件路径
- `wordlist` (str, 可选): 自定义词表文件路径
- `method` (GET | POST | JSON | HEADERS, 可选): 用于扫描的HTTP方法（默认: GET）
- `rateLimit` (int, 可选): 每秒最大请求数（默认: 9999）
- `chunkSize` (int, 可选): 块大小。一次发送的参数数量

**注意:** 必须提供`url`或`textFile`参数中的至少一个

**返回：** 发现的隐藏HTTP参数和分析结果

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "arjun-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/arjun-mcp/server.py", "arjun"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "arjun-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/arjun-mcp/server.py", "arjun"]
    }
  }
}
```

## 使用示例

### 基本GET参数扫描
```python
# 对单个URL进行基本GET参数扫描
url = "https://example.com/search"
```

### 使用不同HTTP方法
```python
# 使用POST方法扫描
url = "https://example.com/login"
method = "POST"

# 检查JSON参数
url = "https://api.example.com/data"
method = "JSON"

# 检查HTTP头部
url = "https://example.com"
method = "HEADERS"
```

### 批量URL扫描
```python
# 从文件扫描多个URL
textFile = "/path/to/urls.txt"
```

### 自定义词表
```python
# 使用自定义参数词表
url = "https://example.com/search"
wordlist = "/path/to/custom_params.txt"
```

### 控制扫描速率
```python
# 限制请求速率以避免触发防护机制
url = "https://example.com/search"
rateLimit = 10  # 每秒10个请求
```

### 调整块大小
```python
# 增加一次发送的参数数量
url = "https://example.com/search"
chunkSize = 25  # 一次发送25个参数
```

## 高级用例

### 完整参数扫描
```python
# 全面扫描所有可能的参数
url = "https://example.com/api"
method = "JSON"
wordlist = "/path/to/comprehensive_params.txt"
rateLimit = 5
chunkSize = 20
```

### 多方法测试
```python
# 对同一URL使用多种方法进行测试（需要多次调用）
url = "https://example.com/endpoint"

# 1. 首先检查GET参数
method = "GET"

# 2. 然后检查POST参数
method = "POST"

# 3. 最后检查JSON参数
method = "JSON"
```

## 输出示例

Arjun的典型输出包含发现的参数和相关信息：

```
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/

[!] Searching for GET parameters
[+] Heuristic scanner found 2 parameters
[+] Reflective scanner found 1 additional parameters

[+] Parameters found: id, query, page
```

## 扫描结果解释

Arjun通过以下方式发现隐藏参数：

1. **启发式扫描**：分析页面内容中可能暗示存在的参数
2. **反射式扫描**：通过发送参数并检查响应中的反射来识别有效参数
3. **模糊测试**：尝试各种常见和自定义参数名称
4. **变化检测**：通过分析不同参数导致的页面变化来确定参数是否有效

## 参数类型说明

Arjun可以发现多种类型的HTTP参数：

- **GET 参数**：URL查询字符串中的参数（例如：`?id=123&page=2`）
- **POST 参数**：表单提交数据（例如：`username=admin&password=123`）
- **JSON 参数**：API请求中的JSON键值对（例如：`{"user_id": 123, "action": "update"}`）
- **HTTP 头部**：自定义HTTP请求头（例如：`X-API-Key`, `Authorization`）

## 故障排除

### Q: 扫描速度很慢
A: 增加`chunkSize`或降低`rateLimit`以平衡速度和准确性

### Q: 未发现任何参数
A: 尝试不同的HTTP方法或使用更广泛的词表

### Q: 收到大量错误响应
A: 降低`rateLimit`以避免触发目标网站的防护机制

### Q: 误报过多
A: 使用更精确的词表或增加Arjun的验证严格性

## 与其他工具结合

### 将Arjun结果用于SQLMap
```bash
# 首先使用Arjun发现参数
arjun -u "https://example.com/page" -o discovered_params.json

# 然后将这些参数传递给SQLMap
sqlmap -u "https://example.com/page" --param-file=discovered_params.json
```

### 与Burp Suite集成
在Burp Suite中使用Arjun发现的参数创建更全面的扫描范围。

## 安全警告

此工具仅用于合法的网络安全测试和管理目的。请确保：
- 只在您拥有或有明确授权的系统上进行扫描
- 遵守所有适用的法律法规
- 考虑使用较低的请求率以减少对目标系统的影响
- 不要使用此工具进行未授权的测试或攻击

## 许可证

本项目基于MIT许可证发布。 