# SQLMap MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供SQLMap功能进行SQL注入测试。

## 功能

提供`do-sqlmap`工具，允许通过MCP协议调用SQLMap进行SQL注入测试。

## 安装要求

- Python 3.8+
- SQLMap (已安装并可在系统PATH中找到，或者提供完整路径)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保SQLMap已安装并可用：
```bash
# 检查SQLMap是否可用
sqlmap --version
```

## 使用方法

### 启动服务器

```bash
python server.py <sqlmap_binary_or_command>
```

例如：
```bash
# 如果sqlmap在系统PATH中
python server.py sqlmap

# 如果使用python3运行sqlmap
python server.py "python3 /path/to/sqlmap.py"

# 使用完整路径
python server.py /usr/local/bin/sqlmap
```

### 工具函数

#### do_sqlmap

运行SQLMap对指定URL进行SQL注入测试。

**参数：**
- `url` (str): 要测试SQL注入的目标URL
- `sqlmap_args` (List[str], 可选): 额外的SQLMap参数列表

**返回：** SQLMap执行的输出结果

**示例SQLMap参数：**

```python
# 基本扫描
sqlmap_args = ["--batch"]

# 使用代理
sqlmap_args = ["--proxy=http://127.0.0.1:8080", "--batch"]

# 指定POST数据
sqlmap_args = ["--data=id=1&name=test", "--batch"]

# 枚举数据库
sqlmap_args = ["--dbs", "--batch"]

# 枚举表
sqlmap_args = ["-D", "database_name", "--tables", "--batch"]

# 转储数据
sqlmap_args = ["-D", "database_name", "-T", "table_name", "--dump", "--batch"]
```

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "sqlmap-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/sqlmap-mcp/server.py", "sqlmap"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "sqlmap-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/sqlmap-mcp/server.py", "sqlmap"]
    }
  }
}
```

## 注意事项

1. 确保已安装SQLMap并可通过命令行访问
2. 使用`--batch`参数避免交互式提示
3. 仅在授权的目标上使用SQL注入测试
4. 遵守相关法律法规和道德准则

## 安全警告

此工具仅用于合法的安全测试目的。请确保：
- 只在您拥有或有明确授权的系统上进行测试
- 遵守所有适用的法律法规
- 以负责任的方式使用安全工具

## 许可证

本项目基于MIT许可证发布。 