# ScoutSuite MCP服务器

本项目是一个基于FastMCP的ScoutSuite云安全审计工具包装器。ScoutSuite是一个开源的多云安全审计工具，能够评估AWS、Azure、Google Cloud Platform和其他云提供商的安全配置。

## 功能特点

- 支持AWS云服务的安全审计
- 可过滤特定服务和区域
- 支持多种认证方式（配置文件、访问密钥）
- 可配置并行工作线程数
- 输出格式化的审计结果

## 安装

### 前提条件

- Python 3.7+
- FastMCP库
- ScoutSuite工具（[安装指南](https://github.com/nccgroup/ScoutSuite/wiki/Setup))

### 安装步骤

1. 克隆仓库
2. 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
python server.py <scoutsuite binary>
```

其中 `<scoutsuite binary>` 是ScoutSuite可执行文件的路径，例如 `/usr/local/bin/scout`。

### API接口

#### do-scoutsuite-aws

执行AWS云安全审计，并返回发现的安全问题。

**参数:**

- `full_report` (布尔值, 可选): 是否返回完整报告，默认为false
- `max_workers` (数字, 可选): ScoutSuite使用的最大并行工作线程数，默认为10
- `services` (字符串数组, 可选): 要包含在扫描范围内的AWS服务名称列表，默认为所有服务
- `skip_services` (字符串数组, 可选): 要从扫描范围中排除的AWS服务名称列表
- `profile` (字符串, 可选): 用于认证的AWS CLI配置文件名称
- `acces_keys` (字符串, 可选): 使用访问密钥而不是配置文件进行认证
- `access_key_id` (字符串, 可选): 用于认证的AWS访问密钥ID
- `secret_acces_key` (字符串, 可选): 用于认证的AWS秘密访问密钥
- `session_token` (字符串, 可选): 临时AWS会话令牌（如果使用临时凭证）
- `regions` (字符串, 可选): 要包含在扫描中的AWS区域的逗号分隔列表，默认为所有区域
- `exclude_regions` (字符串, 可选): 要从扫描中排除的AWS区域的逗号分隔列表
- `ip_ranges` (字符串, 可选): 包含已知IP范围的JSON文件路径，用于匹配发现的问题
- `ip_ranges_name_key` (字符串, 可选): IP范围文件中映射到已知CIDR显示名称的键

**返回:**

JSON格式的审计结果，包含按服务分组的安全发现。

- 如果 `full_report` 为 `true`，则返回详细的发现信息
- 如果 `full_report` 为 `false` 或未提供，则仅返回发现名称列表

**示例:**

```json
{
  "iam": [
    "access-keys-rotation",
    "credential-report",
    "inline-policies"
  ],
  "s3": [
    "bucket-no-logging",
    "bucket-no-mfa-delete",
    "bucket-no-versioning"
  ]
}
```

## 认证方式

ScoutSuite支持以下AWS认证方式：

1. **AWS配置文件**: 使用 `profile` 参数指定AWS CLI配置文件名称
2. **访问密钥**: 使用 `access_key_id` 和 `secret_acces_key` 参数提供凭证
3. **临时凭证**: 使用 `session_token` 参数提供临时会话令牌

## 常见问题

### 无法找到ScoutSuite结果文件

如果出现"Could not find ScoutSuite results file path in output"错误，请确保ScoutSuite有足够的权限创建和写入文件。

### 区域过滤不生效

使用 `regions` 参数时，确保区域名称格式正确（例如：`us-east-1,eu-west-1`）。

## 安全注意事项

- 避免在代码或环境变量中硬编码AWS凭证
- 使用最小权限原则配置用于扫描的IAM用户或角色
- 定期轮换访问密钥

## 许可证

[MIT](LICENSE)

## 参考资料

- [ScoutSuite官方文档](https://github.com/nccgroup/ScoutSuite/wiki)
- [AWS安全最佳实践](https://aws.amazon.com/security/security-learning/) 