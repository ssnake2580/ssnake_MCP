# Waybackurls MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Waybackurls功能进行历史URL发现。

## 功能

提供`do-waybackurls`工具，允许通过MCP协议调用Waybackurls从Wayback Machine存档中获取域名的历史URL。

## 安装要求

- Python 3.8+
- Waybackurls (已安装并可在系统PATH中找到，或者提供完整路径)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Waybackurls已安装：
```bash
# 检查Waybackurls是否可用
waybackurls --help
```

## 使用方法

### 启动服务器

```bash
python server.py <waybackurls_binary>
```

例如：
```bash
# 如果waybackurls在系统PATH中
python server.py waybackurls

# 使用完整路径
python server.py /usr/local/bin/waybackurls
```

### 工具函数

#### do_waybackurls

从Wayback Machine存档中获取指定域名的历史URL。这有助于发现历史端点、遗忘的API路径以及可能无法从当前网站版本直接访问或链接的潜在易受攻击的URL。

**参数：**
- `target` (str): 要获取历史URL的目标域名（例如：example.com）
- `noSub` (bool, 可选): 当设置为true时，只获取指定域名的URL，排除所有子域名

**返回：** 从Wayback Machine发现的历史URL列表

**功能说明：**
- 支持包含或排除子域名的URL发现
- 提供完整的历史URL数据
- 帮助发现隐藏或遗忘的端点

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "waybackurls-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/waybackurls-mcp/server.py", "waybackurls"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "waybackurls-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/waybackurls-mcp/server.py", "waybackurls"]
    }
  }
}
```

## 使用示例

```python
# 获取域名的所有历史URL（包括子域名）
target = "example.com"
noSub = False

# 仅获取主域名的历史URL（排除子域名）
target = "example.com"
noSub = True
```

## 注意事项

1. 确保已安装Waybackurls并可通过命令行访问
2. 工具依赖于Wayback Machine的数据可用性
3. 仅在授权的目标上使用历史URL发现
4. 遵守相关法律法规和道德准则

## 安全警告

此工具仅用于合法的安全测试和侦察目的。请确保：
- 只在您拥有或有明确授权的域名上进行历史URL发现
- 遵守所有适用的法律法规
- 以负责任的方式使用侦察工具

## 许可证

本项目基于MIT许可证发布。 