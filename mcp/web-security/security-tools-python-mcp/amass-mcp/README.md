# Amass MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Amass功能进行高级子域名枚举和信息收集。

## 功能

提供`amass`工具，允许通过MCP协议使用Amass进行以下操作：

- **子域名枚举** (enum): 发现目标域名的子域名
- **情报收集** (intel): 从各种来源收集目标域名的情报信息

## 安装要求

- Python 3.8+
- Amass (已安装并可访问)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Amass已安装：
```bash
# 检查amass是否可用
amass -version

# 在Linux上安装amass
snap install amass  # 使用snap安装
# 或使用GO安装
go install -v github.com/owasp-amass/amass/v3/...@master

# 在macOS上安装amass
brew install amass
```

## 使用方法

### 启动服务器

```bash
python server.py <amass_binary>
```

例如：
```bash
# 如果amass在系统PATH中
python server.py amass

# 使用完整路径
python server.py /usr/bin/amass
```

### 工具函数

#### amass

高级子域名枚举和信息收集工具。

**参数：**
- `subcommand` (enum | intel): 指定Amass操作模式
  - `enum`: 执行子域名枚举和网络映射
  - `intel`: 从各种来源收集目标域名的情报
- `domain` (str, 可选): 要进行侦察的目标域名(例如: example.com)
- `intel_whois` (bool, 可选): 是否在情报收集中包含WHOIS数据
- `intel_organization` (str, 可选): 在情报收集过程中要搜索的组织名称
- `enum_type` (active | passive, 可选): 枚举方法类型
  - `active`: 包括DNS解析和与目标的潜在网络交互
  - `passive`: 仅使用第三方来源的信息，不与目标直接交互
- `enum_brute` (bool, 可选): 是否执行暴力破解子域名发现
- `enum_brute_wordlist` (str, 可选): 用于暴力破解操作的自定义词表文件路径

**返回：** Amass侦察和枚举的结果

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "amass-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/amass-mcp/server.py", "amass"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "amass-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/amass-mcp/server.py", "amass"]
    }
  }
}
```

## 使用示例

### 子域名枚举（Enum模式）

#### 基本子域名枚举
```python
# 对example.com进行基本子域名枚举（默认为主动模式）
subcommand = "enum"
domain = "example.com"
```

#### 被动子域名枚举
```python
# 仅使用第三方数据源（无直接交互）
subcommand = "enum"
domain = "example.com"
enum_type = "passive"
```

#### 暴力破解子域名
```python
# 启用暴力破解以发现更多子域名
subcommand = "enum"
domain = "example.com"
enum_brute = True
```

#### 使用自定义词表
```python
# 使用自定义词表进行暴力破解
subcommand = "enum"
domain = "example.com"
enum_brute = True
enum_brute_wordlist = "/path/to/custom_wordlist.txt"
```

### 情报收集（Intel模式）

#### 基于域名的情报
```python
# 收集与特定域名相关的情报
subcommand = "intel"
domain = "example.com"
intel_whois = True  # 启用WHOIS查询（使用域名时必需）
```

#### 基于组织的情报
```python
# 收集与特定组织相关的情报
subcommand = "intel"
intel_organization = "Example Corp"
intel_whois = True  # 可选但推荐
```

## 高级用例

### 全面的子域名枚举
```python
# 结合多种技术进行全面的子域名枚举
subcommand = "enum"
domain = "example.com"
enum_brute = True
# 其他高级选项可通过amass命令行选项配置
```

### 多域名情报收集
```python
# 对多个相关域名进行情报收集
# 注意：需要分别运行每个域名
domains = ["example.com", "example.org", "example.net"]
for domain in domains:
    subcommand = "intel"
    domain = domain
    intel_whois = True
```

## 结果解析

### 子域名枚举结果
Amass enum子命令的典型输出包含发现的子域名列表：
```
www.example.com
api.example.com
mail.example.com
dev.example.com
...
```

### 情报收集结果
Amass intel子命令的输出包含有关域名或组织的多种情报：
```
ASN: 15169
CIDR: 172.217.0.0/16
netname: GOOGLE
...
```

## 性能和安全注意事项

### 性能考虑
- 对大型域名进行枚举可能需要大量时间和资源
- 被动模式比主动模式更快但可能发现的子域名更少
- 暴力破解模式消耗更多资源但可能发现更多子域名

### 安全和道德考虑
- 仅在授权的情况下使用此工具
- 被动模式对目标域名的影响最小
- 暴力破解可能对目标DNS服务器造成负载，请谨慎使用
- 请遵守所有相关法律和法规

## 工作原理

Amass结合了多种技术来发现子域名和收集情报：

1. **被动发现**：
   - 证书透明度日志查询
   - 搜索引擎结果解析
   - API集成（Shodan、Censys等）
   - WHOIS信息分析

2. **主动技术**：
   - DNS解析和区域转移
   - 暴力破解
   - 排列变换和字典攻击

3. **情报聚合**：
   - ASN和网络范围识别
   - 组织关联
   - 基础设施映射

## 故障排除

### Q: Amass运行缓慢
A: 考虑使用passive模式或限制搜索范围

### Q: 结果较少
A: 尝试启用暴力破解(enum_brute)或确认目标域名正确

### Q: 错误："对域名参数whois是必需的"
A: 使用intel模式时，如果提供了domain参数，则需要设置intel_whois=True

### Q: 内存使用过高
A: Amass可能消耗大量内存，考虑在资源更丰富的系统上运行

## 安全警告

此工具仅用于合法的网络安全测试和管理目的。请确保：
- 只在您拥有或有明确授权的域名上进行扫描
- 遵守所有适用的法律法规
- 考虑使用被动模式以减少对目标的影响
- 谨慎使用暴力破解功能

## 许可证

本项目基于MIT许可证发布。 