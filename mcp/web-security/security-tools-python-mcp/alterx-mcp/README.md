# Alterx MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Alterx功能进行域名变异和模式生成。

## 功能

提供`do-alterx`工具，允许通过MCP协议使用Alterx生成域名排列组合，用于子域名发现和DNS枚举。

## 安装要求

- Python 3.8+
- Alterx (已安装并可访问)
- FastMCP库

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Alterx已安装：
```bash
# 通常通过GO安装
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# 检查alterx是否可用
alterx -h
```

## 使用方法

### 启动服务器

```bash
python server.py <alterx_binary>
```

例如：
```bash
# 如果alterx在系统PATH中
python server.py alterx

# 使用完整路径
python server.py /usr/local/bin/alterx
```

### 工具函数

#### do_alterx

执行Alterx，一个使用基于模式的排列组合生成域名词表的工具，用于子域名发现和DNS枚举。

**参数：**
- `domain` (str): 作为创建排列组合基础的目标域名或子域名（接受标准输入、逗号分隔的值或文件路径）
- `pattern` (str): 生成词表变化的模式模板。可以使用逗号分隔指定多个模式。
- `outputFilePath` (str, 可选): 生成的词表应保存的路径（可选）

**模式类型说明：**

| 模式类型 | 示例 | 说明 |
|---------|------|------|
| 破折号模式 | `{{word}}-{{sub}}.{{suffix}}` | 生成：dev-api.example.com |
|  | `{{sub}}-{{word}}.{{suffix}}` | 生成：api-dev.example.com |
| 点分模式 | `{{word}}.{{sub}}.{{suffix}}` | 生成：word.api.example.com |
|  | `{{sub}}.{{word}}.{{suffix}}` | 生成：api.word.example.com |
| 迭代模式 | `{{sub}}{{number}}.{{suffix}}` | 生成：api1.example.com, api2.example.com |
| 替换模式 | `{{word}}.{{suffix}}` | 完全替换当前子域名 |
| 无分隔符模式 | `{{sub}}{{word}}.{{suffix}}` | 生成：apidev.example.com |
| 区域前缀模式 | `{{region}}.{{sub}}.{{suffix}}` | 生成：us-east.api.example.com |
| 组合模式 | `{{word}}{{number}}.{{suffix}}` | 组合单词和数字 |

**返回：** 基于指定模式生成的域名排列组合

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "alterx-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/alterx-mcp/server.py", "alterx"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "alterx-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/alterx-mcp/server.py", "alterx"]
    }
  }
}
```

## 使用示例

### 基本域名变异
```python
# 使用单个模式生成域名变体
domain = "api.example.com"
pattern = "{{word}}-{{sub}}.{{suffix}}"
```

### 使用多个模式
```python
# 使用多个模式同时生成多种变体
domain = "api.example.com"
pattern = "{{word}}-{{sub}}.{{suffix}},{{sub}}-{{word}}.{{suffix}}"
```

### 迭代模式示例
```python
# 生成数字序列的子域名
domain = "api.example.com"
pattern = "{{sub}}{{number}}.{{suffix}}"
```

### 保存结果到文件
```python
# 将生成的域名变体保存到文件
domain = "api.example.com"
pattern = "{{word}}.{{sub}}.{{suffix}}"
outputFilePath = "/tmp/domain_variants.txt"
```

### 环境变体
```python
# 生成不同环境的子域名
domain = "api.example.com"
pattern = "{{env}}-{{sub}}.{{suffix}}"
```

### 使用破折号和点的组合
```python
# 创建更复杂的子域名变体
domain = "api.example.com"
pattern = "{{word}}-{{sub}}.{{suffix}},{{word}}.{{sub}}.{{suffix}}"
```

## 模式详解

### 基本变量

- `{{sub}}`: 输入域名的子域名部分（例如：在"api.example.com"中是"api"）
- `{{suffix}}`: 输入域名的后缀部分（例如：在"api.example.com"中是"example.com"）
- `{{word}}`: 从内置或自定义字典中获取的单词
- `{{number}}`: 数字序列（默认为1-10）
- `{{env}}`: 环境名称（如dev、staging、prod等）
- `{{region}}`: 区域名称（如us-east、eu-west等）

### 组合技巧

1. **前缀添加**：`{{word}}.{{sub}}.{{suffix}}`
   - 输入：api.example.com
   - 输出：dev.api.example.com, admin.api.example.com, ...

2. **后缀添加**：`{{sub}}.{{word}}.{{suffix}}`
   - 输入：api.example.com
   - 输出：api.dev.example.com, api.admin.example.com, ...

3. **破折号组合**：`{{sub}}-{{word}}.{{suffix}}`
   - 输入：api.example.com
   - 输出：api-dev.example.com, api-admin.example.com, ...

4. **数字序列**：`{{sub}}{{number}}.{{suffix}}`
   - 输入：api.example.com
   - 输出：api1.example.com, api2.example.com, ...

5. **环境变体**：`{{env}}-{{sub}}.{{suffix}}`
   - 输入：api.example.com
   - 输出：dev-api.example.com, staging-api.example.com, ...

## 高级用例

### 大规模子域名生成
```python
# 为企业Web应用生成常见子域名变体
domain = "example.com"
pattern = (
    "{{word}}.{{suffix}},"  # 直接子域名
    "{{word}}-{{word}}.{{suffix}},"  # 组合子域名
    "{{env}}-{{word}}.{{suffix}},"  # 环境子域名
    "{{word}}.{{word}}.{{suffix}},"  # 嵌套子域名
    "{{region}}.{{word}}.{{suffix}}"  # 区域子域名
)
```

### 目标特定变体
```python
# 专注于特定应用类型的子域名
domain = "api.example.com"
pattern = (
    "{{sub}}-v1.{{suffix}},"  # API版本
    "{{sub}}-v2.{{suffix}},"
    "{{sub}}-beta.{{suffix}},"
    "{{sub}}-sandbox.{{suffix}},"
    "{{sub}}-test.{{suffix}}"
)
```

## 输出示例

Alterx的典型输出是每行一个生成的域名变体：

```
dev-api.example.com
test-api.example.com
api-dev.example.com
stage-api.example.com
api.dev.example.com
api.test.example.com
api1.example.com
api2.example.com
...
```

## 结合其他工具

Alterx生成的子域名列表可以与其他工具结合使用：

### 与shuffledns结合
```bash
# 生成域名变体后使用shuffledns进行DNS解析
alterx -l example.com -p "{{word}}.{{suffix}}" | shuffledns -r /path/to/resolvers.txt -o resolved.txt
```

### 与httpx结合
```bash
# 生成域名变体后使用httpx检查活跃的Web服务
alterx -l example.com -p "{{word}}.{{suffix}}" | httpx -o active_domains.txt
```

## 性能考虑

- **模式数量**：使用多个模式会生成更多变体，但也会增加处理时间
- **输入规模**：处理大型域名列表需要更多资源
- **输出控制**：考虑使用outputFilePath参数将结果保存到文件，而不是仅返回到终端

## 故障排除

### Q: 生成的域名变体过多
A: 减少模式数量或使用更具体的模式

### Q: 未生成任何输出
A: 检查域名格式和模式语法是否正确

### Q: 内存使用过高
A: 处理大型输出时，确保将结果保存到文件中

## 安全警告

此工具仅用于合法的网络安全测试和管理目的。请确保：
- 只在您拥有或有明确授权的域名上进行枚举
- 遵守所有适用的法律法规
- 谨慎使用生成的域名列表，避免对目标系统造成过大负载
- 不要使用生成的列表进行未授权的扫描或攻击

## 许可证

本项目基于MIT许可证发布。 