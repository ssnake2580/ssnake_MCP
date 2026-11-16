# Assetfinder MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Assetfinder功能进行子域名发现。

## 功能

提供`do-assetfinder`工具，允许通过MCP协议调用Assetfinder进行子域名和相关域名发现。

## 安装要求

- Python 3.8+
- Assetfinder (已安装并可在系统PATH中找到，或者提供完整路径)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Assetfinder已安装：
```bash
# 检查Assetfinder是否可用
assetfinder --help
```

## 使用方法

### 启动服务器

```bash
python server.py <assetfinder_binary>
```

例如：
```bash
# 如果assetfinder在系统PATH中
python server.py assetfinder

# 使用完整路径
python server.py /usr/local/bin/assetfinder
```

### 工具函数

#### do_assetfinder

使用Assetfinder查找指定域名的相关域名和子域名。

**参数：**
- `target` (str): 要发现子域名的根域名（例如：example.com）

**返回：** 发现的子域名和相关域名列表

**功能说明：**
- 自动使用`-subs-only`参数，只返回子域名
- 自动移除输出中的ANSI颜色代码
- 提供清洁的文本输出

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "assetfinder-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/assetfinder-mcp/server.py", "assetfinder"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "assetfinder-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/assetfinder-mcp/server.py", "assetfinder"]
    }
  }
}
```

## 注意事项

1. 确保已安装Assetfinder并可通过命令行访问
2. 工具会自动添加`-subs-only`参数来专注于子域名发现
3. 仅在授权的目标上使用域名枚举工具
4. 遵守相关法律法规和道德准则

## 安全警告

此工具仅用于合法的安全测试和侦察目的。请确保：
- 只在您拥有或有明确授权的域名上进行枚举
- 遵守所有适用的法律法规
- 以负责任的方式使用侦察工具

## 许可证

本项目基于MIT许可证发布。 