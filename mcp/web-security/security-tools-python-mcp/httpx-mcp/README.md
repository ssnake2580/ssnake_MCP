# Httpx MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Httpx功能进行HTTP服务发现和探测。

## 功能

提供`httpx`工具，允许通过MCP协议使用Httpx扫描指定域名，检测活跃的HTTP/HTTPS服务。

## 安装要求

- Python 3.8+
- Httpx (已安装并可访问)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Httpx已安装：
```bash
# 检查httpx是否可用
httpx --help
```

## 使用方法

### 启动服务器

```bash
python server.py <httpx_binary>
```

例如：
```bash
# 如果httpx在系统PATH中
python server.py httpx

# 使用完整路径
python server.py /usr/local/bin/httpx
```

### 工具函数

#### httpx

扫描指定的目标域名，检测80和443等端口上的活跃HTTP/HTTPS服务。

**参数：**
- `target` (List[str]): 要扫描HTTP和HTTPS服务的域名列表（例如：["example.com", "test.com"]）
- `ports` (List[int], 可选): 要扫描的端口列表
- `probes` (List[str], 可选): 探测选项列表

**探测选项说明：**

| 选项 | 功能描述 |
|------|----------|
| `status-code` | 显示响应状态码 |
| `content-length` | 显示响应内容长度 |
| `content-type` | 显示响应内容类型 |
| `location` | 显示响应重定向位置 |
| `favicon` | 显示'/favicon.ico'文件的mmh3哈希 |
| `hash` | 显示响应体哈希（支持：md5,mmh3,simhash,sha1,sha256,sha512） |
| `jarm` | 显示jarm指纹哈希 |
| `response-time` | 显示响应时间 |
| `line-count` | 显示响应体行数 |
| `word-count` | 显示响应体字数 |
| `title` | 显示页面标题 |
| `body-preview` | 显示响应体前N个字符（默认100） |
| `web-server` | 显示服务器名称 |
| `tech-detect` | 基于wappalyzer数据集显示使用的技术 |
| `method` | 显示HTTP请求方法 |
| `websocket` | 显示使用websocket的服务器 |
| `ip` | 显示主机IP |
| `cname` | 显示主机CNAME |
| `extract-fqdn` | 从响应体和头部获取域名和子域名 |
| `asn` | 显示主机ASN信息 |
| `cdn` | 显示使用的CDN/WAF（默认true） |
| `probe` | 显示探测状态 |

**返回：** Httpx扫描结果，显示活跃的HTTP/HTTPS服务

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "httpx-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/httpx-mcp/server.py", "httpx"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "httpx-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/httpx-mcp/server.py", "httpx"]
    }
  }
}
```

## 使用示例

### 基本扫描
```python
# 基本HTTP服务检测
target = ["example.com", "test.com"]

# 扫描指定端口
target = ["example.com"]
ports = [80, 443, 8080, 8443]

# 使用探测选项
target = ["example.com"]
probes = ["status-code", "title", "tech-detect"]
```

### 高级用法
```python
# 全面信息收集
target = ["example.com"]
ports = [80, 443, 8080, 8443, 9000]
probes = [
    "status-code", "content-length", "title", 
    "web-server", "tech-detect", "ip", "asn"
]

# 性能分析
target = ["example.com"]
probes = ["response-time", "content-length", "line-count", "word-count"]

# 安全探测
target = ["example.com"]
probes = ["jarm", "hash", "cdn", "websocket"]
```

## 工作原理

1. **目标处理**：将域名列表转换为httpx可识别的格式
2. **端口配置**：动态构建端口扫描参数
3. **探测配置**：根据选项动态添加探测参数
4. **执行扫描**：调用httpx工具进行HTTP/HTTPS服务探测
5. **结果处理**：清理ANSI颜色代码，返回纯文本结果

## 使用场景

- **服务发现**：快速识别Web服务
- **端口扫描**：检测HTTP/HTTPS服务端口
- **技术栈识别**：分析Web应用使用的技术
- **安全评估**：收集目标服务信息
- **性能监控**：分析响应时间和服务状态

## 性能优化

- **并发控制**：httpx自动处理并发请求
- **超时设置**：合理设置请求超时时间
- **探测选择**：根据需要选择必要的探测选项
- **目标分组**：合理分组扫描目标

## 注意事项

1. 确保已正确安装httpx工具
2. 合理设置扫描参数，避免对目标造成过大压力
3. 某些探测选项可能增加扫描时间
4. 仅在授权的目标上进行HTTP服务扫描
5. 遵守相关法律法规和道德准则

## 安全警告

此工具仅用于合法的安全测试和服务发现目的。请确保：
- 只在您拥有或有明确授权的目标上进行扫描
- 遵守所有适用的法律法规
- 以负责任的方式使用网络扫描工具
- 避免对目标服务造成不必要的负载

## 许可证

本项目基于MIT许可证发布。 