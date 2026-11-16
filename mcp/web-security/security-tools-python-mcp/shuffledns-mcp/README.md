# Shuffledns MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Shuffledns功能进行DNS暴力破解。

## 功能

提供`shuffledns`工具，允许通过MCP协议使用Shuffledns进行DNS域名暴力破解和解析。

## 安装要求

- Python 3.8+
- Shuffledns (已安装并可访问)
- Massdns (已安装并可访问)
- FastMCP库
- DNS解析器文件
- 域名字典文件

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Shuffledns和Massdns已安装：
```bash
# 检查工具是否可用
shuffledns --help
massdns --help
```

## 使用方法

### 启动服务器

```bash
python server.py <shuffledns_binary> <massdns_binary>
```

例如：
```bash
# 如果工具在系统PATH中
python server.py shuffledns massdns

# 使用完整路径
python server.py /usr/local/bin/shuffledns /usr/local/bin/massdns
```

### 工具函数

#### shuffledns

执行DNS暴力破解操作，支持多种模式和自定义配置。

**参数：**
- `target` (str): 要扫描的域名（例如：example.com）
- `resolver` (str): DNS解析器文件路径
- `mode` (ShufflednsMode): 操作模式（bruteforce、resolve、filter）
- `wordlist` (str): 用于暴力破解的字典文件路径
- `rateLimit` (int, 可选): 请求速率限制

**操作模式说明：**
- **bruteforce**: DNS暴力破解模式
- **resolve**: DNS解析模式
- **filter**: DNS过滤模式

**返回：** DNS暴力破解操作的结果

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "shuffledns-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/shuffledns-mcp/server.py", "shuffledns", "massdns"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "shuffledns-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/shuffledns-mcp/server.py", "shuffledns", "massdns"]
    }
  }
}
```

## 工作原理

1. **工具集成**：结合Shuffledns和Massdns的功能
2. **DNS暴力破解**：使用字典文件进行DNS查询
3. **多模式支持**：支持暴力破解、解析、过滤三种模式
4. **速率控制**：支持自定义请求速率限制
5. **结果输出**：提供清洁的文本输出

## 所需文件

### DNS解析器文件
需要一个包含DNS服务器地址的文件，例如：
```
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
```

### 字典文件
需要一个包含子域名字典的文件，例如：
```
www
mail
ftp
admin
api
dev
test
staging
```

## 使用示例

```python
# 基本DNS暴力破解
target = "example.com"
resolver = "/path/to/resolvers.txt"
mode = "bruteforce"
wordlist = "/path/to/subdomains.txt"

# 带速率限制的暴力破解
target = "example.com"
resolver = "/path/to/resolvers.txt"
mode = "bruteforce"
wordlist = "/path/to/subdomains.txt"
rateLimit = 1000
```

## 注意事项

1. 确保已正确安装Shuffledns和Massdns
2. 需要准备有效的DNS解析器文件和字典文件
3. 合理设置速率限制，避免对目标造成过大压力
4. 仅在授权的目标上进行DNS暴力破解
5. 遵守相关法律法规和道德准则

## 性能优化

- **解析器选择**：选择快速可靠的DNS解析器
- **字典优化**：使用针对性的字典文件
- **速率调整**：根据网络条件调整请求速率
- **并发控制**：合理设置并发数量

## 安全警告

此工具仅用于合法的安全测试和DNS分析目的。请确保：
- 只在您拥有或有明确授权的域名上进行DNS暴力破解
- 遵守所有适用的法律法规
- 以负责任的方式使用DNS枚举工具
- 避免对DNS基础设施造成不必要的负载

## 许可证

本项目基于MIT许可证发布。 