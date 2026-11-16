# Katana MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Katana功能进行Web爬虫和端点发现。

## 功能

提供`do-katana`工具，允许通过MCP协议使用Katana执行快速、可配置的Web爬取，识别端点、参数和JavaScript基于的链接。

## 安装要求

- Python 3.8+
- Katana (已安装并可访问)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Katana已安装：
```bash
# 通常通过GO安装
go install github.com/projectdiscovery/katana/cmd/katana@latest

# 检查katana是否可用
katana -h
```

## 使用方法

### 启动服务器

```bash
python server.py <katana_binary>
```

例如：
```bash
# 如果katana在系统PATH中
python server.py katana

# 使用完整路径
python server.py /usr/local/bin/katana
```

### 工具函数

#### do_katana

对给定的目标URL执行快速且可配置的Web爬取，识别端点、参数和基于JavaScript的链接。

**参数：**
- `target` (List[str]): 要扫描端点和JavaScript链接的目标URL列表（例如，https://example.com）
- `exclude` (List[str], 可选): 要排除在爬取范围之外的URL或正则表达式模式列表
- `depth` (int, 可选): 最大爬取深度（例如，3表示三级深度）
- `js_crawl` (bool, 可选): 启用JavaScript文件的爬取和端点提取
- `jsluice` (bool, 可选): 启用JSluice解析，用于更深入的基于JavaScript的链接分析（内存密集型）
- `headers` (List[str], 可选): 要包含在请求中的自定义头部或Cookie列表（格式：Header:Value）
- `strategy` (depth-first | breadth-first, 可选): 使用的爬取策略："depth-first"或"breadth-first"（默认为depth-first）
- `headless` (bool, 可选): 启用基于无头浏览器的混合爬取（实验性）
- `system_chrome` (bool, 可选): 使用本地安装的Chrome浏览器，而非内置浏览器
- `show_browser` (bool, 可选): 即使在无头模式下也显示浏览器窗口（用于调试/视觉检查）

**返回：** 从爬取的目标发现的URL、端点和参数

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "katana-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/katana-mcp/server.py", "katana"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "katana-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/katana-mcp/server.py", "katana"]
    }
  }
}
```

## 使用示例

### 基本网站爬取
```python
# 爬取单个网站
target = ["https://example.com"]
```

### 多目标爬取
```python
# 同时爬取多个网站
target = [
    "https://example.com",
    "https://test.example.org"
]
```

### 限制爬取深度
```python
# 限制爬取深度为2层
target = ["https://example.com"]
depth = 2
```

### 启用JavaScript爬取
```python
# 启用JavaScript文件的爬取和端点提取
target = ["https://example.com"]
js_crawl = True
```

### 深度JavaScript分析
```python
# 启用更深入的JavaScript链接分析
target = ["https://example.com"]
js_crawl = True
jsluice = True  # 注意：这会增加内存使用
```

### 使用自定义请求头
```python
# 添加自定义头部进行认证或模拟特定浏览器
target = ["https://example.com"]
headers = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Authorization: Bearer token123",
    "Cookie: session=abc123"
]
```

### 排除特定URL
```python
# 排除特定路径或URL模式
target = ["https://example.com"]
exclude = [
    "https://example.com/logout",
    "https://example.com/admin/*",
    ".*/logout.*"
]
```

### 使用广度优先爬取
```python
# 使用广度优先策略而非默认的深度优先
target = ["https://example.com"]
strategy = "breadth-first"
```

### 浏览器模式爬取
```python
# 启用无头浏览器爬取（用于渲染JavaScript内容）
target = ["https://example.com"]
headless = True
```

### 使用系统Chrome
```python
# 使用本地安装的Chrome而非内置浏览器
target = ["https://example.com"]
headless = True
system_chrome = True
```

### 可视化调试
```python
# 在无头模式下显示浏览器窗口（用于调试）
target = ["https://example.com"]
headless = True
show_browser = True
```

## 高级用例

### 全面网站映射
```python
# 深度爬取网站以创建完整映射
target = ["https://example.com"]
depth = 5
js_crawl = True
jsluice = True
strategy = "breadth-first"
```

### 单页应用(SPA)爬取
```python
# 针对JavaScript驱动的单页应用优化的爬取
target = ["https://spa-example.com"]
js_crawl = True
jsluice = True
headless = True
```

### 大型网站快速爬取
```python
# 对大型网站进行有限但高效的爬取
target = ["https://large-site.com"]
depth = 2
strategy = "breadth-first"
# 排除可能导致无限循环的部分
exclude = [
    ".*/tag/.*",
    ".*/page/[0-9]+/.*",
    ".*/date/.*"
]
```

## 输出示例

Katana的典型输出包含发现的URL列表，每行一个：

```
https://example.com/
https://example.com/about
https://example.com/products?id=123
https://example.com/api/v1/users
https://example.com/js/main.js
https://example.com/css/style.css
https://example.com/blog/article-1
https://example.com/login
https://api.example.com/v2/data
```

## 爬取技术

Katana使用多种技术来发现URL和端点：

1. **常规HTML爬取**：解析HTML并提取链接
2. **JavaScript解析**：从JS文件中提取API端点和URL
3. **表单分析**：识别表单操作和可能的参数
4. **JavaScript执行**（带有headless选项）：运行JavaScript以发现动态生成的链接
5. **模式匹配**：识别URL模式和API端点结构

## 性能考虑

- **深度限制**：增加`depth`会显著增加爬取时间和资源使用
- **JavaScript分析**：启用`js_crawl`和`jsluice`会增加CPU和内存使用
- **浏览器模式**：`headless`选项会显著增加资源使用，但对SPA很有效
- **爬取策略**：
  - `depth-first`在查找深层链接时效果好
  - `breadth-first`在映射整个站点结构时更全面

## 故障排除

### Q: 爬取速度很慢
A: 减小`depth`值或禁用`jsluice`/`headless`选项

### Q: 内存使用过高
A: 禁用`jsluice`选项，这是一个内存密集型功能

### Q: 找不到JavaScript生成的链接
A: 启用`headless`选项让Katana执行JavaScript代码

### Q: 爬虫陷入特定路径循环
A: 使用`exclude`参数排除导致循环的路径模式

## 安全和道德考虑

此工具仅用于合法的网络安全测试和管理目的。请确保：
- 只在您拥有或有明确授权的网站上进行爬取
- 遵守网站的robots.txt指令
- 考虑网站所有者的资源限制
- 避免过快或过于激进的爬取
- 不要使用此工具进行未授权的数据收集

## 集成其他工具

Katana的输出可以轻松用于其他安全工具：

### 与Nuclei结合
```bash
# 使用Katana发现URL，然后用Nuclei扫描漏洞
katana -u https://example.com -jc | nuclei -l -
```

### 与FFuF结合
```bash
# 使用Katana发现URL，然后用FFuF进行模糊测试
katana -u https://example.com | grep "\.php" | ffuf -w - -u FUZZ?param=test
```

## 许可证

本项目基于MIT许可证发布。 