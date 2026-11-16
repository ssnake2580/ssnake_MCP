#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import aiohttp
from fastmcp import McpServer, Content, ContentItem, ResponseContent
from fastmcp.schema import StringParam, as_params
from typing import Dict, List, Any, Tuple, Optional

# 获取当前脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))

# 加载配置文件
with open(os.path.join(script_dir, "owasp_headers_remove.json"), "r") as f:
    remove_headers_data = json.load(f)

with open(os.path.join(script_dir, "owasp_headers_add.json"), "r") as f:
    add_headers_data = json.load(f)

# 创建服务器实例
server = McpServer(name="http-headers-security", version="1.0.0")


async def fetch_http_headers(target: str) -> List[str]:
    """
    获取目标URL的HTTP响应头
    
    Args:
        target (str): 目标URL
    
    Returns:
        List[str]: HTTP头部列表，格式为"header_name: header_value"
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target, timeout=100, ssl=False) as response:
                return [f"{key}: {value}" for key, value in response.headers.items()]
    except Exception as e:
        raise Exception(f"Failed to fetch headers: {str(e)}")


async def find_matching_remove_headers(headers: List[str]) -> List[str]:
    """
    查找需要移除的HTTP头部
    
    Args:
        headers (List[str]): HTTP头部列表
    
    Returns:
        List[str]: 匹配的需要移除的HTTP头部列表
    """
    remove_headers = remove_headers_data["headers"]
    
    return [
        header for header in headers
        if any(
            h.lower() == header.split(':', 1)[0].strip().lower()
            for h in remove_headers
        )
    ]


async def find_matching_added_headers(headers: List[str]) -> List[str]:
    """
    查找需要添加的HTTP头部
    
    Args:
        headers (List[str]): 当前HTTP头部列表
    
    Returns:
        List[str]: 需要添加的HTTP头部列表
    """
    add_headers = add_headers_data["headers"]
    existing_header_names = [header.split(':', 1)[0].strip().lower() for header in headers]
    
    return [
        f"{header['name']}: {header['value']}"
        for header in add_headers
        if header['name'].lower() not in existing_header_names
    ]


@server.tool(
    name="analyze-http-header",
    description="Perform security analysis of HTTP response headers for a web application. This tool examines HTTP headers against OWASP security best practices, identifying both potentially dangerous headers that should be removed and recommended security headers that are missing. Results include specific recommendations for improving security posture.",
    params=as_params(
        target=StringParam(
            description="Target URL to analyze (e.g., https://example.com). The tool will make a request to this URL and evaluate its HTTP response headers for security issues."
        )
    )
)
async def analyze_http_header(target: str) -> ResponseContent:
    """
    分析HTTP响应头安全性
    
    Args:
        target (str): 目标URL
    
    Returns:
        ResponseContent: 分析结果
    """
    headers = await fetch_http_headers(target)
    remove_headers = await find_matching_remove_headers(headers)
    add_headers = await find_matching_added_headers(headers)
    
    result = {
        "removeHeaders": remove_headers if remove_headers else ["No headers to remove"],
        "addedHeaders": add_headers if add_headers else ["No headers to add"]
    }
    
    return ResponseContent(
        content=Content(
            items=[
                ContentItem(
                    type="text",
                    text=json.dumps(result, indent=2, ensure_ascii=False)
                )
            ]
        )
    )


if __name__ == "__main__":
    server.run() 