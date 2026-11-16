# Smuggler MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Smuggler功能来检测HTTP Request Smuggling漏洞。

## 功能

提供`do_smuggler`工具，允许通过MCP协议使用Smuggler检测HTTP Request Smuggling漏洞，包括CL.TE和TE.CL类型的攻击。

## 安装要求

- Python 3.8+
- Smuggler.py脚本（已下载并可访问）
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 下载Smuggler工具：
```bash
# 下载smuggler.py
wget https://raw.githubusercontent.com/defparam/smuggler/master/smuggler.py
# 或从官方仓库克隆
git clone https://github.com/defparam/smuggler.git
```

## 使用方法

### 启动服务器

```bash
python server.py <python路径> <smuggler.py路径>
```

例如：
```bash
# 使用系统Python和当前目录的smuggler.py
python server.py python smuggler.py

# 使用完整路径
python server.py /usr/bin/python3 /path/to/smuggler.py
```

### 工具函数

#### do_smuggler

运行Smuggler来检测HTTP Request Smuggling漏洞。

**参数：**
- `url` (str): 要检测HTTP Request Smuggling的目标URL
- `smuggler_args` (List[str], 可选): 额外的smuggler参数

**支持的smuggler参数：**

| 参数 | 功能描述 |
|------|----------|
| `-m, --method METHOD` | 指定要使用的HTTP方法（默认：POST） |
| `-v, --vhost VHOST` | 指定要使用的虚拟主机 |
| `-l, --len` | 在所有请求中启用Content-Length头 |
| `-c, --configfile FILE` | 指定配置文件以加载负载 |
| `-x` | 在第一个发现时退出 |
| `-t, --timeout TIMEOUT` | Socket超时值（默认：5） |
| `-verify VERIFY` | 使用更多请求验证发现；never、quick或thorough（默认：quick） |

**返回：** 
包含以下内容的字典：
- `content`: 包含Smuggler输出文本的列表
- `metadata`: 包含结构化漏洞发现的元数据
  - `findings`: 包含`cl_te`和`te_cl`漏洞列表
    - `mutation`: 触发漏洞的变异类型
    - `severity`: 漏洞严重性（high/medium）

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "smuggler-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/smuggler-mcp/server.py", "python", "/path/to/smuggler.py"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "smuggler-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/smuggler-mcp/server.py", "python", "/path/to/smuggler.py"]
    }
  }
}
```

## 使用示例

### 基本检测
```python
# 基本HTTP Request Smuggling检测
url = "https://example.com"

# 使用POST方法检测
url = "https://example.com"
smuggler_args = ["-m", "POST"]

# 设置超时时间
url = "https://example.com"
smuggler_args = ["-t", "10"]
```

### 高级用法
```python
# 全面漏洞检测
url = "https://example.com"
smuggler_args = [
    "-m", "POST",
    "-l",  # 启用Content-Length头
    "-t", "10",  # 设置超时
    "-verify", "thorough"  # 彻底验证
]

# 快速退出模式
url = "https://example.com"
smuggler_args = [
    "-x",  # 在第一个发现时退出
    "-verify", "quick"
]

# 使用虚拟主机
url = "https://example.com"
smuggler_args = [
    "-v", "api.example.com",
    "-m", "GET"
]

# 使用配置文件
url = "https://example.com"
smuggler_args = [
    "-c", "/path/to/config.txt",
    "-verify", "never"
]
```

## 漏洞类型说明

### CL.TE (Content-Length Transfer-Encoding)
- 前端服务器使用Content-Length头
- 后端服务器使用Transfer-Encoding头
- 可能导致请求走私攻击

### TE.CL (Transfer-Encoding Content-Length)  
- 前端服务器使用Transfer-Encoding头
- 后端服务器使用Content-Length头
- 可能导致请求走私攻击

## 工作原理

1. **目标验证**：验证URL格式和可达性
2. **参数构建**：构建smuggler命令行参数
3. **执行检测**：运行smuggler.py进行漏洞检测
4. **结果解析**：解析输出中的CL.TE和TE.CL漏洞
5. **严重性评估**：根据发现标记确定漏洞严重性
6. **结构化输出**：返回文本输出和结构化元数据

## 使用场景

- **Web安全评估**：检测HTTP Request Smuggling漏洞
- **渗透测试**：识别潜在的请求走私攻击点
- **安全审计**：验证Web应用程序的安全性
- **合规检查**：确保Web服务符合安全标准
- **漏洞验证**：验证修复后的安全状态

## 性能优化

- **超时设置**：合理设置Socket超时时间
- **验证模式**：根据需要选择验证级别（never/quick/thorough）
- **快速退出**：使用`-x`参数在发现漏洞时快速退出
- **并发控制**：避免同时对同一目标进行多次检测

## 注意事项

1. 确保已正确下载和配置smuggler.py脚本
2. 仅在授权的目标上进行漏洞检测
3. 某些检测可能产生异常流量，请谨慎使用
4. 建议在测试环境中先验证工具配置
5. 注意目标服务器的负载和响应时间

## 安全警告

此工具仅用于合法的安全测试和漏洞评估目的。请确保：
- 只在您拥有或有明确授权的目标上进行检测
- 遵守所有适用的法律法规和道德准则
- 以负责任的方式使用安全测试工具
- 避免对生产环境造成不必要的影响
- 妥善处理检测过程中发现的敏感信息

## 参考资源

- [Smuggler项目](https://github.com/defparam/smuggler)
- [HTTP Request Smuggling基础知识](https://portswigger.net/web-security/request-smuggling)
- [OWASP Request Smuggling指南](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)

## 许可证

本项目基于MIT许可证发布。 