# Crt.sh MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供crt.sh功能，从SSL证书日志中发现子域名。

## 功能

提供`crtsh`工具，允许通过MCP协议查询crt.sh数据库，从SSL证书日志中发现指定域名的子域名。

## 安装要求

- Python 3.8+
- 网络连接（用于访问crt.sh API）
- FastMCP库
- aiohttp库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
python server.py
```

注意：crtsh-mcp不需要额外的命令行参数，因为它直接通过HTTP API调用crt.sh服务。

### 工具函数

#### crtsh

从SSL证书日志中发现子域名。crt.sh是一个免费的证书透明度日志搜索引擎，可以帮助发现通过SSL证书暴露的子域名。

**参数：**
- `target` (str): 要分析的目标域名（例如：example.com）

**返回：** 从SSL证书日志中发现的子域名的JSON格式列表

**功能说明：**
- 查询crt.sh证书透明度日志
- 解析证书中的域名信息
- 过滤和去重子域名
- 返回格式化的JSON结果

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "crtsh-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/crtsh-mcp/server.py"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "crtsh-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/crtsh-mcp/server.py"]
    }
  }
}
```

## 工作原理

1. **API调用**：向crt.sh的JSON API发送查询请求
2. **数据解析**：解析返回的SSL证书数据
3. **域名提取**：从证书的`name_value`字段提取域名
4. **过滤去重**：使用正则表达式过滤出相关子域名并去重
5. **结果返回**：以JSON格式返回发现的子域名列表

## 使用场景

- **子域名枚举**：发现目标域名的所有子域名
- **资产发现**：识别组织的网络资产
- **安全评估**：寻找被遗忘或未保护的子域名
- **证书审计**：了解域名的SSL证书使用情况

## 注意事项

1. 需要稳定的网络连接访问crt.sh API
2. crt.sh的数据依赖于证书透明度日志，可能不包含所有子域名
3. 结果的完整性取决于目标域名的SSL证书使用情况
4. 仅在授权的目标上使用子域名发现
5. 遵守相关法律法规和道德准则

## 优势

- **无需本地工具**：直接通过API调用，无需安装额外工具
- **证书透明度**：基于公开的证书透明度日志
- **高效准确**：专门针对SSL证书中的域名信息
- **实时数据**：获取最新的证书日志信息

## 安全警告

此工具仅用于合法的安全测试和侦察目的。请确保：
- 只在您拥有或有明确授权的域名上进行子域名发现
- 遵守所有适用的法律法规
- 以负责任的方式使用侦察工具

## 许可证

本项目基于MIT许可证发布。 