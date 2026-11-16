# MobSF MCP服务器

本项目是一个基于FastMCP的MobSF移动应用安全分析框架的API包装器。MobSF (Mobile Security Framework) 是一个自动化的移动应用（Android/iOS/Windows）渗透测试、恶意软件分析和安全评估框架。

## 功能特点

- 上传移动应用程序（APK、IPA、APPX）到MobSF进行安全分析
- 扫描移动应用程序，检测安全漏洞
- 获取详细的扫描日志
- 生成全面的JSON格式安全分析报告
- 查看最近执行的安全扫描列表

## 安装

### 前提条件

- Python 3.7+
- FastMCP库
- 已安装并运行的MobSF服务器（[安装指南](https://github.com/MobSF/Mobile-Security-Framework-MobSF))

### 安装步骤

1. 克隆仓库
2. 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
python server.py <baseUrl> <apiKey>
```

其中：
- `<baseUrl>` 是MobSF API的基础URL，例如 http://localhost:8000
- `<apiKey>` 是MobSF API密钥，可以在MobSF设置中找到

### API接口

#### uploadFile

上传移动应用文件（APK、IPA或APPX）到MobSF进行安全分析。这是在使用其他分析功能之前必须执行的第一步。

**参数:**

- `file`: 要上传的文件路径

**返回:**

JSON格式的上传响应，包含文件名、哈希值和扫描类型。

**示例:**

```json
{
  "file_name": "example.apk",
  "hash": "3a8c42e63f89a952a7d9790d2fa2985c",
  "scan_type": "apk"
}
```

#### scanFile

扫描已上传到MobSF的文件。此工具分析已上传的移动应用程序以查找安全漏洞，并提供全面的安全评估报告。

**参数:**

- `hash`: 要扫描的文件哈希值
- `reScan` (可选): 设置为true以强制重新扫描文件，默认为false

**返回:**

JSON格式的扫描结果。

#### getScanLogs

使用哈希值检索先前分析的移动应用程序的详细扫描日志。这些日志包含有关扫描过程和遇到的任何问题的信息。

**参数:**

- `hash`: 获取扫描日志的文件哈希值

**返回:**

JSON格式的扫描日志。

#### getJsonReport

为已扫描的移动应用程序生成并检索JSON格式的全面安全分析报告。该报告包括有关安全漏洞、权限、API调用和其他安全相关信息的详细发现。

**参数:**

- `hash`: 获取报告的文件哈希值

**返回:**

JSON格式的详细安全分析报告。

#### getRecentScans

检索MobSF服务器上最近执行的安全扫描列表，显示已分析的移动应用程序、其状态和基本扫描信息。

**参数:**

- `page` (可选): 结果的页码，默认为1
- `pageSize` (可选): 结果的页面大小，默认为10

**返回:**

JSON格式的最近扫描列表。

## 工作流程示例

1. 上传APK文件
   ```bash
   # 返回的哈希值为：3a8c42e63f89a952a7d9790d2fa2985c
   ```

2. 扫描上传的文件
   ```bash
   # 使用上一步返回的哈希值
   ```

3. 获取扫描报告
   ```bash
   # 使用相同的哈希值获取详细报告
   ```

## 安全注意事项

- 确保MobSF服务器在安全的环境中运行
- 避免分析未知来源的可疑应用程序
- 定期更新MobSF以获取最新的安全检查

## 常见问题

### 无法连接到MobSF服务器

检查MobSF服务器是否正在运行，以及baseUrl是否正确。

### API密钥无效

确保使用的API密钥是正确的，可以在MobSF设置页面查看或重新生成API密钥。

### 文件上传失败

检查文件是否存在且格式有效（APK、IPA或APPX）。

## 许可证

[MIT](LICENSE)

## 参考资料

- [MobSF官方文档](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki)
- [MobSF API文档](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/mobsf-rest-api) 