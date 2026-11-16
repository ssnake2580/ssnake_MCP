#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import asyncio
import re
from fastmcp import McpServer, Content, ContentItem, ResponseContent
from fastmcp.schema import StringParam, BooleanParam, NumberParam, ArrayParam, as_params
from typing import Dict, List, Any, Optional, Union

# 检查命令行参数
if len(sys.argv) < 2:
    print("Usage: python server.py <scoutsuite binary>", file=sys.stderr)
    sys.exit(1)

# ScoutSuite二进制文件路径
SCOUTSUITE_BINARY = sys.argv[1]


def extract_report_js_path(output: str) -> Optional[str]:
    """
    从ScoutSuite输出中提取结果文件路径
    
    Args:
        output (str): ScoutSuite命令输出
    
    Returns:
        Optional[str]: 结果文件路径，如果没有找到则返回None
    """
    regex = r"Saving data to (scoutsuite-report/scoutsuite-results/scoutsuite_results_[\w\-]+\.js)"
    match = re.search(regex, output)
    return match.group(1) if match else None


def get_findings_from_scoutsuite(file_path: str, full_report: bool) -> Dict[str, Any]:
    """
    解析ScoutSuite结果文件
    
    Args:
        file_path (str): ScoutSuite结果文件路径
        full_report (bool): 是否返回完整报告
    
    Returns:
        Dict[str, Any]: 解析后的结果
    """
    # 读取文件内容
    with open(file_path, 'r') as f:
        file_content = f.read()
    
    # 提取scoutsuite_results变量
    # 注意：这里使用简单的字符串处理，而不是vm模块，因为Python中没有直接等价物
    js_content = file_content.strip()
    if js_content.startswith('var scoutsuite_results = '):
        js_content = js_content[len('var scoutsuite_results = '):]
    if js_content.endswith(';'):
        js_content = js_content[:-1]
    
    # 解析JSON
    results = json.loads(js_content)
    services = results.get('services', {})
    
    services_with_findings = {}
    
    # 提取发现结果
    for service_name, service_data in services.items():
        findings = service_data.get('findings', {})
        if findings and len(findings) > 0:
            if full_report:
                services_with_findings[service_name] = findings
            else:
                services_with_findings[service_name] = list(findings.keys())
    
    return services_with_findings


# 创建服务器实例
server = McpServer(name="scoutsuite", version="1.0.0")


@server.tool(
    name="do-scoutsuite-aws",
    description="Performs an AWS cloud security audit using Scout Suite for the given target settings, allowing service/region filtering and multiple authentication methods.",
    params=as_params(
        full_report=BooleanParam(
            description="Whether to return the full detailed report (true) or just finding names (false)",
            default=False,
            required=False
        ),
        max_workers=NumberParam(
            description="Maximum number of parallel worker threads used by Scout Suite (default: 10)",
            required=False
        ),
        services=ArrayParam(
            items=StringParam(),
            description="A list of AWS service names to include in scope (default: all services)",
            required=False
        ),
        skip_services=ArrayParam(
            items=StringParam(),
            description="A list of AWS service names to exclude from scope",
            required=False
        ),
        profile=StringParam(
            description="Use a named AWS CLI profile for authentication",
            required=False
        ),
        acces_keys=StringParam(
            description="Run using access keys instead of profile (use access_key_id, secret_access_key, and optionally session_token)",
            required=False
        ),
        access_key_id=StringParam(
            description="AWS Access Key ID used for authentication",
            required=False
        ),
        secret_acces_key=StringParam(
            description="AWS Secret Access Key used for authentication",
            required=False
        ),
        session_token=StringParam(
            description="Temporary AWS session token (if using temporary credentials)",
            required=False
        ),
        regions=StringParam(
            description="Comma-separated list of AWS regions to include in the scan (default: all regions)",
            required=False
        ),
        exclude_regions=StringParam(
            description="Comma-separated list of AWS regions to exclude from the scan",
            required=False
        ),
        ip_ranges=StringParam(
            description="Path to JSON file(s) containing known IP ranges to match findings against",
            required=False
        ),
        ip_ranges_name_key=StringParam(
            description="Key in the IP ranges file that maps to the display name of a known CIDR",
            required=False
        )
    )
)
async def do_scoutsuite_aws(
    full_report: bool = False,
    max_workers: Optional[int] = None,
    services: Optional[List[str]] = None,
    skip_services: Optional[List[str]] = None,
    profile: Optional[str] = None,
    acces_keys: Optional[str] = None,
    access_key_id: Optional[str] = None,
    secret_acces_key: Optional[str] = None,
    session_token: Optional[str] = None,
    regions: Optional[str] = None,
    exclude_regions: Optional[str] = None,
    ip_ranges: Optional[str] = None,
    ip_ranges_name_key: Optional[str] = None
) -> ResponseContent:
    """
    执行AWS云安全审计
    
    Args:
        full_report (bool): 是否返回完整报告
        max_workers (Optional[int]): 最大并行工作线程数
        services (Optional[List[str]]): 要扫描的AWS服务列表
        skip_services (Optional[List[str]]): 要跳过的AWS服务列表
        profile (Optional[str]): AWS CLI配置文件名
        acces_keys (Optional[str]): 是否使用访问密钥而不是配置文件
        access_key_id (Optional[str]): AWS访问密钥ID
        secret_acces_key (Optional[str]): AWS秘密访问密钥
        session_token (Optional[str]): 临时AWS会话令牌
        regions (Optional[str]): 要包含的AWS区域列表
        exclude_regions (Optional[str]): 要排除的AWS区域列表
        ip_ranges (Optional[str]): 包含已知IP范围的JSON文件路径
        ip_ranges_name_key (Optional[str]): IP范围文件中映射到已知CIDR显示名称的键
    
    Returns:
        ResponseContent: 审计结果
    """
    # 构建ScoutSuite命令参数
    scout_suite_args = ["aws", "--force", "--no-browser"]
    
    if max_workers is not None:
        scout_suite_args.extend(["--max-workers", str(max_workers)])
    
    if services:
        scout_suite_args.append("--services")
        for service in services:
            scout_suite_args.append(service)
    
    if skip_services:
        scout_suite_args.append("--skip")
        for service in skip_services:
            scout_suite_args.append(service)
    
    if profile:
        scout_suite_args.extend(["--profile", profile])
    
    if acces_keys:
        scout_suite_args.append("--access-keys")
    
    if access_key_id:
        scout_suite_args.extend(["--access-key-id", access_key_id])
    
    if secret_acces_key:
        scout_suite_args.extend(["--secret-access-key", secret_acces_key])
    
    if session_token:
        scout_suite_args.extend(["--session-token", session_token])
    
    if regions:
        scout_suite_args.extend(["--regions", regions])
    
    if exclude_regions:
        scout_suite_args.extend(["--exclude-regions", exclude_regions])
    
    if ip_ranges:
        scout_suite_args.extend(["--ip-ranges", ip_ranges])
    
    if ip_ranges_name_key:
        scout_suite_args.extend(["--ip-ranges-name-key", ip_ranges_name_key])
    
    # 创建命令并捕获输出
    cmd = [SCOUTSUITE_BINARY] + scout_suite_args
    output = ""
    
    try:
        # 运行ScoutSuite命令
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        output = stdout.decode() + stderr.decode()
        
        # 检查命令是否成功
        if process.returncode != 0:
            raise Exception(f"ScoutSuite exited with code {process.returncode}")
        
        # 提取结果文件路径
        report_path = extract_report_js_path(output)
        if not report_path:
            raise Exception("Could not find ScoutSuite results file path in output")
        
        # 解析结果
        findings = get_findings_from_scoutsuite(report_path, full_report)
        
        # 返回结果
        return ResponseContent(
            content=Content(
                items=[
                    ContentItem(
                        type="text",
                        text=json.dumps(findings, indent=2, ensure_ascii=False)
                    )
                ]
            )
        )
    
    except Exception as e:
        raise Exception(f"Error running ScoutSuite: {str(e)}")


if __name__ == "__main__":
    server.run() 