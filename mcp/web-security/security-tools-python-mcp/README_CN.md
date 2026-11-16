[ENGLISH](README.md)

# MCP for Security - Python版本

这是一个安全工具的MCP (Model Context Protocol) 服务器集合的Python重构版本，使用FastMCP库实现。

## 🌟 项目来源与声明

### 致谢原作者
本项目是基于 **[cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security)** 的 JavaScript/TypeScript 版本进行的完整Python重构。感谢 **cyproxio** 开源了这个优秀的安全工具MCP服务器集合，为网络安全工具的标准化提供了重要贡献。

### 重构说明
⚠️ **重要声明：**
- 本项目**完全由Claude 4 AI**进行重构，从JavaScript/TypeScript转换为Python
- **未经过人工实机验证**，可能存在运行错误或功能缺陷
- 代码逻辑基于原版本进行翻译和适配，但可能存在理解偏差
- **请用户自行分析代码**，谨慎在生产环境中使用
- 如发现问题，**欢迎提交PR**或Issue来帮助改进项目

## 🎯 项目目标

将20个JavaScript版本的安全工具MCP服务器完整重构为Python版本，保持：
- ✅ 100% API兼容性（理论上）
- ✅ 相同的功能和参数
- ✅ 独立运行，无相互依赖
- ✅ 详细的中文文档

## 📁 项目结构

```
mcp-for-security-python/
├── README.md                    # 本文件
├── sqlmap-mcp/                  # SQL注入测试工具
├── assetfinder-mcp/             # 子域名发现工具
├── waybackurls-mcp/             # 历史URL发现工具
├── crtsh-mcp/                   # SSL证书日志查询工具
├── shuffledns-mcp/              # DNS暴力破解工具
├── httpx-mcp/                   # HTTP服务探测工具
├── ffuf-mcp/                    # Web模糊测试工具
├── nuclei-mcp/                  # 漏洞扫描工具
├── nmap-mcp/                    # 网络扫描工具
├── masscan-mcp/                 # 高速端口扫描工具
├── alterx-mcp/                  # 域名变异生成工具
├── arjun-mcp/                   # HTTP参数发现工具
├── katana-mcp/                  # 网络爬虫工具
├── sslscan-mcp/                 # SSL/TLS安全扫描工具
├── http-headers-security-mcp/   # HTTP头安全检查工具
├── mobsf-mcp/                   # 移动应用安全分析工具
├── scoutsuite-mcp/              # 云安全审计工具
├── smuggler-mcp/                # HTTP请求走私漏洞检测
├── amass-mcp/                   # 资产发现与侦察工具
└── wpsscan-mcp/                 # WordPress安全扫描工具
```

## 🚀 MCP服务器列表

### ✅ 已完成 (20/20 - 100%)

#### 基础工具类
1. **assetfinder-mcp** - 子域名发现工具
   - 功能：快速发现目标域名的子域名
   - 特点：自动ANSI颜色代码清理

2. **waybackurls-mcp** - 历史URL发现工具
   - 功能：从Wayback Machine获取历史URL
   - 特点：支持包含/排除子域名选项

3. **crtsh-mcp** - SSL证书日志查询工具
   - 功能：从证书透明度日志发现子域名
   - 特点：API调用，无需本地工具

4. **shuffledns-mcp** - DNS暴力破解工具
   - 功能：高效的DNS解析和暴力破解
   - 特点：集成massdns，支持多种模式

5. **alterx-mcp** - 域名变异生成工具
   - 功能：生成域名变异用于子域名发现
   - 特点：支持多种变异模式和自定义模板

#### 扫描工具类
6. **httpx-mcp** - HTTP服务探测工具
   - 功能：快速HTTP/HTTPS服务发现
   - 特点：丰富的探测选项和并发处理

7. **nmap-mcp** - 网络扫描工具
   - 功能：全面的网络发现和端口扫描
   - 特点：完整的nmap参数支持

8. **masscan-mcp** - 高速端口扫描工具
   - 功能：高速大规模端口扫描
   - 特点：支持自定义速率和端口范围

9. **nuclei-mcp** - 漏洞扫描工具
   - 功能：基于模板的漏洞扫描
   - 特点：多工具函数，包含标签获取API

10. **sslscan-mcp** - SSL/TLS安全扫描工具
    - 功能：SSL/TLS配置和漏洞检测
    - 特点：支持多种SSL/TLS测试选项

#### 模糊测试类
11. **ffuf-mcp** - Web模糊测试工具
    - 功能：高性能Web目录和参数模糊测试
    - 特点：完整的参数配置支持

12. **arjun-mcp** - HTTP参数发现工具
    - 功能：发现隐藏的HTTP GET/POST参数
    - 特点：支持多种检测模式和自定义字典

#### 网络爬虫类
13. **katana-mcp** - 网络爬虫工具
    - 功能：快速网络爬虫和端点发现
    - 特点：支持JavaScript渲染和深度爬取

#### 漏洞测试类
14. **sqlmap-mcp** - SQL注入测试工具
    - 功能：自动化SQL注入检测和利用
    - 特点：支持丰富的参数配置

15. **smuggler-mcp** - HTTP请求走私漏洞检测
    - 功能：检测HTTP Request Smuggling漏洞
    - 特点：支持CL.TE和TE.CL类型检测

16. **wpsscan-mcp** - WordPress安全扫描工具
    - 功能：WordPress网站安全漏洞扫描
    - 特点：支持插件、主题、用户枚举等

#### 安全审计类
17. **http-headers-security-mcp** - HTTP头安全检查工具
    - 功能：分析HTTP响应头的安全配置
    - 特点：基于OWASP标准进行安全评估

18. **mobsf-mcp** - 移动应用安全分析工具
    - 功能：Android/iOS移动应用安全分析
    - 特点：API集成，支持静态和动态分析

19. **scoutsuite-mcp** - 云安全审计工具
    - 功能：多云平台安全配置审计
    - 特点：支持AWS、Azure、GCP等云平台

20. **amass-mcp** - 网络资产发现工具
    - 功能：全面的网络资产发现和侦察
    - 特点：支持多种数据源和深度侦察

## 🛠️ 技术特性

### 统一架构
- **框架**：FastMCP 2.0+
- **语言**：Python 3.8+
- **异步处理**：asyncio
- **类型注解**：typing模块

### 核心功能
- **工具函数**：`@mcp.tool()`装饰器
- **异步执行**：subprocess + asyncio
- **错误处理**：统一的异常捕获和返回
- **文档支持**：完整的docstring和参数说明

### 实现模式

#### 1. 命令行工具包装
```python
@mcp.tool()
async def tool_name(target: str, args: List[str] = None) -> str:
    cmd = [tool_command] + construct_args(target, args)
    process = await asyncio.create_subprocess_exec(...)
    stdout, _ = await process.communicate()
    return process_output(stdout)
```

#### 2. API调用集成
```python
@mcp.tool()
async def api_tool(target: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get(api_url) as response:
            data = await response.json()
            return process_api_data(data)
```

#### 3. 多工具函数
```python
@mcp.tool()
async def primary_function(...) -> str:
    # 主要功能

@mcp.tool()
async def helper_function(...) -> str:
    # 辅助功能（如获取配置、标签等）
```

## 📦 安装和使用

### 环境要求
```bash
# Python环境
python >= 3.8

# 安装FastMCP
pip install fastmcp>=2.0.0

# 根据需要安装额外依赖
pip install aiohttp>=3.8.0  # 用于API调用的工具
```

### 通用使用流程

1. **进入工具目录**
```bash
cd mcp-for-security-python/[tool-name]-mcp/
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **启动服务器**
```bash
# 对于命令行工具（大部分）
python server.py [tool-binary-path]

# 对于API工具（如mobsf-mcp）
python server.py [api-base-url] [api-key]

# 对于脚本工具（如smuggler-mcp）
python server.py [python-path] [script-path]
```

4. **配置MCP客户端**
```json
{
  "mcpServers": {
    "tool-name-mcp": {
      "command": "python",
      "args": ["/path/to/tool-mcp/server.py", "tool-binary"]
    }
  }
}
```

## 🔧 开发指南

### 重构标准
1. **API兼容性**：保持与JavaScript版本完全相同的接口
2. **函数描述**：直接使用原版的docstring内容
3. **参数处理**：支持相同的参数类型和结构
4. **错误处理**：统一的异常处理和返回格式
5. **文档完整性**：每个工具都有详细的README.md

### 代码模板
```python
#!/usr/bin/env python3
"""
Tool MCP Server
Description of the tool functionality.
"""

import sys
import asyncio
from typing import List, Optional
from mcp.server.fastmcp import FastMCP

# Command line argument handling
if len(sys.argv) < 2:
    print("Usage: python server.py <tool-binary>", file=sys.stderr)
    sys.exit(1)

tool_command = sys.argv[1]
mcp = FastMCP("tool-name", version="1.0.0")

@mcp.tool()
async def tool_function(param: str, optional_param: Optional[List[str]] = None) -> str:
    """Tool function description"""
    # Implementation
    pass

if __name__ == "__main__":
    mcp.run()
```

## 🐛 已知问题与限制

### 可能存在的问题
- **未实机测试**：所有代码均为AI重构，未经实际运行验证
- **依赖兼容性**：可能存在Python库版本兼容问题
- **参数解析**：命令行参数构造可能存在错误
- **异常处理**：错误处理逻辑可能不够完善
- **性能优化**：未针对Python特性进行优化

### 如何贡献
我们欢迎社区贡献来改进这个项目：

1. **测试验证**：在实际环境中测试工具功能
2. **问题报告**：通过GitHub Issues报告发现的问题
3. **代码修复**：提交PR修复发现的错误
4. **功能改进**：优化性能或添加新功能
5. **文档完善**：改进文档和使用示例

## 🛡️ 安全提醒

⚠️ **重要安全警告**

这些工具仅用于合法的安全测试和研究目的：

1. **授权使用**：只在您拥有或有明确授权的系统上使用
2. **法律合规**：遵守所有适用的法律法规
3. **负责任披露**：发现的漏洞应通过负责任的方式披露
4. **道德使用**：以提高安全性为目标，而非恶意攻击
5. **测试验证**：由于未经实机测试，请先在安全环境中验证功能

## 📄 许可证

本项目基于MIT许可证发布。

原项目 [cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security) 同样基于MIT许可证。

## 🤝 贡献

欢迎贡献代码来改进项目：

1. Fork项目
2. 创建特性分支
3. 测试你的更改
4. 提交Pull Request

特别欢迎：
- 实机测试结果反馈
- Bug修复
- 性能优化
- 文档改进

## 📞 联系方式

如有问题或建议，请通过GitHub Issues联系。

## 🙏 致谢

- 感谢 **[cyproxio](https://github.com/cyproxio)** 开源了原版的JavaScript MCP服务器集合
- 感谢所有安全工具的原作者们提供了这些优秀的安全工具
- 感谢MCP协议和FastMCP库的开发者们

---

**MCP for Security - Python版本** | 让安全工具更易用、更强大 🚀 