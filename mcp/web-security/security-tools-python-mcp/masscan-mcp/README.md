# Masscan MCP Server (Python版本)

这是一个基于FastMCP库的Python MCP服务器，用于提供Masscan功能进行高速端口扫描。

## 功能

提供`do-masscan`工具，允许通过MCP协议使用Masscan进行快速、大规模的端口扫描。

## 安装要求

- Python 3.8+
- Masscan (已安装并可访问)
- FastMCP库
- 适当的系统权限（Masscan通常需要root权限）

## 安装

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 确保Masscan已安装：
```bash
# 检查masscan是否可用
masscan --version

# 在Linux上安装masscan
sudo apt-get install masscan  # Ubuntu/Debian
sudo yum install masscan      # CentOS/RHEL

# 在macOS上安装masscan
brew install masscan
```

## 使用方法

### 启动服务器

```bash
python server.py <masscan_binary>
```

例如：
```bash
# 如果masscan在系统PATH中
python server.py masscan

# 使用完整路径
python server.py /usr/bin/masscan
```

### 工具函数

#### do_masscan

运行Masscan进行高速端口扫描。Masscan是一个快速端口扫描器，主要输入参数是要扫描的IP地址/范围和端口号。

**参数：**
- `target` (str): 目标信息（例如：1.1.1.1, 192.168.1.0/24, 10.0.0.1-10.0.0.255）
- `port` (str): 目标端口（例如：80, 1-1000, 80,443,8080）
- `masscan_args` (List[str], 可选): 额外的masscan参数

**常用参数说明：**

| 参数 | 功能描述 |
|------|----------|
| `--max-rate` | 每秒发送的最大包数（例如：--max-rate 1000） |
| `--rate` | 每秒包数（旧版选项） |
| `--banners` | 获取横幅信息 |
| `--excludefile` | 从文件中排除IP地址 |
| `--includefile` | 从文件中包含IP地址 |
| `--randomize-hosts` | 随机化扫描主机顺序 |
| `--wait` | 等待响应包的时间（默认10秒） |
| `--retries` | 重发包的次数（默认3次） |
| `--interactive` | 实时输出 |
| `--output-format` | 输出格式：json, xml, list, grepable |
| `--output-filename` | 输出到文件 |

**返回：** Masscan高速端口扫描的结果

## 配置MCP客户端

### Claude Desktop

在`~/.config/claude-desktop/claude_desktop_config.json`中添加：

```json
{
  "mcpServers": {
    "masscan-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/masscan-mcp/server.py", "masscan"]
    }
  }
}
```

### Cursor

在`~/.cursor/mcp.json`中添加：

```json
{
  "mcpServers": {
    "masscan-mcp": {
      "command": "python",
      "args": ["/path/to/mcp-for-security-python/masscan-mcp/server.py", "masscan"]
    }
  }
}
```

## 使用示例

### 基本端口扫描
```python
# 扫描单个IP的常用端口
target = "192.168.1.1"
port = "80,443,22,21,25,53,110,993,995"

# 扫描IP范围的特定端口
target = "192.168.1.0/24"
port = "80"

# 扫描端口范围
target = "10.0.0.1"
port = "1-1000"
```

### 高级扫描配置
```python
# 高速扫描（谨慎使用）
target = "192.168.1.0/24"
port = "1-65535"
masscan_args = ["--max-rate", "10000"]

# 获取服务横幅
target = "192.168.1.1"
port = "80,443"
masscan_args = ["--banners", "--max-rate", "1000"]

# 输出到JSON文件
target = "192.168.1.0/24"
port = "80,443,8080"
masscan_args = [
    "--max-rate", "1000",
    "--output-format", "json",
    "--output-filename", "/tmp/scan_results.json"
]
```

### 大规模网络扫描
```python
# 扫描大型网络
target = "10.0.0.0/8"
port = "80,443"
masscan_args = [
    "--max-rate", "100000",
    "--randomize-hosts",
    "--wait", "3"
]
```

## 性能和安全注意事项

### 性能优化
- **速率控制**：合理设置`--max-rate`，避免网络拥塞
- **目标分组**：大型扫描可以分批进行
- **系统资源**：确保足够的内存和CPU资源
- **网络带宽**：考虑网络带宽限制

### 权限要求
```bash
# Masscan通常需要root权限
sudo python server.py masscan

# 或者给予必要的网络权限
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan
```

### 扫描策略
- **内网扫描**：适合快速发现内网服务
- **互联网扫描**：需要遵守法律法规和道德准则
- **速率限制**：避免对目标网络造成过大负载

## 工作原理

1. **高速包发送**：Masscan使用异步I/O发送大量探测包
2. **并行处理**：同时扫描多个IP和端口
3. **状态检测**：分析响应包确定端口状态
4. **结果整理**：格式化输出扫描结果

## 输出格式示例

### 标准输出
```
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 443/tcp on 192.168.1.1
Discovered open port 22/tcp on 192.168.1.1
```

### JSON输出
```json
[
  {"ip": "192.168.1.1", "port": 80, "protocol": "tcp", "status": "open"},
  {"ip": "192.168.1.1", "port": 443, "protocol": "tcp", "status": "open"},
  {"ip": "192.168.1.1", "port": 22, "protocol": "tcp", "status": "open"}
]
```

## 常见问题

### Q: 扫描速度慢
A: 调整`--max-rate`参数，但要注意网络负载

### Q: 权限不足错误
A: 确保以root权限运行或设置适当的capabilities

### Q: 目标无响应
A: 检查目标是否在线，调整`--wait`时间

### Q: 防火墙阻止
A: 某些网络可能阻止大量扫描流量

## 安全警告

此工具仅用于合法的网络安全测试和管理目的。请确保：
- 只在您拥有或有明确授权的网络上进行扫描
- 遵守所有适用的法律法规
- 避免对网络基础设施造成不必要的负载
- 以负责任的方式使用高速扫描工具

## 许可证

本项目基于MIT许可证发布。 