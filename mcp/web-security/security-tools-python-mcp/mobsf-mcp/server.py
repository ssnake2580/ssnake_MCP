#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import aiohttp
import asyncio
from fastmcp import McpServer, Content, ContentItem, ResponseContent
from fastmcp.schema import StringParam, BooleanParam, NumberParam, as_params
from typing import Dict, List, Any, Optional, Union

# 检查命令行参数
if len(sys.argv) < 3:
    print("Usage: python server.py <baseUrl> <apiKey>", file=sys.stderr)
    sys.exit(1)

# MobSF API 配置
BASE_URL = sys.argv[1]
API_KEY = sys.argv[2]

# 确保 BASE_URL 不以 '/' 结尾
if BASE_URL.endswith('/'):
    BASE_URL = BASE_URL[:-1]


class MobSFClient:
    """MobSF API 客户端"""
    
    def __init__(self, base_url: str, api_key: str):
        """
        初始化 MobSF 客户端
        
        Args:
            base_url (str): MobSF API 基础 URL
            api_key (str): MobSF API 密钥
        """
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            'Authorization': api_key,
            'X-Mobsf-Api-Key': api_key
        }
    
    async def _send_request(self, url: str, method: str = 'GET', data: Any = None, 
                           headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        发送 HTTP 请求到 MobSF API
        
        Args:
            url (str): 请求 URL
            method (str): HTTP 方法 (GET, POST 等)
            data (Any, optional): 请求数据
            headers (Dict[str, str], optional): 请求头
            params (Dict[str, Any], optional): URL 参数
        
        Returns:
            Dict[str, Any]: API 响应数据
        """
        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)
            
        try:
            async with aiohttp.ClientSession() as session:
                if method == 'GET':
                    async with session.get(url, headers=request_headers, params=params) as response:
                        if response.status != 200:
                            error_text = await response.text()
                            raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                        return await response.json()
                elif method == 'POST':
                    async with session.post(url, headers=request_headers, data=data, params=params) as response:
                        if response.status != 200:
                            error_text = await response.text()
                            raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                        return await response.json()
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
        except aiohttp.ClientError as e:
            raise Exception(f"Network error: {str(e)}")
    
    async def upload_file(self, file_path: str) -> Dict[str, Any]:
        """
        上传文件到 MobSF 进行分析
        
        Args:
            file_path (str): 要上传的文件路径
        
        Returns:
            Dict[str, Any]: 上传响应
        """
        url = f"{self.base_url}/api/v1/upload"
        
        try:
            data = aiohttp.FormData()
            data.add_field('file', open(file_path, 'rb'), filename=os.path.basename(file_path))
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=self.headers, data=data) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                    return await response.json()
        except Exception as e:
            raise Exception(f"Error uploading file: {str(e)}")
    
    async def scan_file(self, hash_value: str, rescan: bool = False) -> Dict[str, Any]:
        """
        扫描已上传到 MobSF 的文件
        
        Args:
            hash_value (str): 要扫描的文件哈希值
            rescan (bool, optional): 是否强制重新扫描
        
        Returns:
            Dict[str, Any]: 扫描结果
        """
        url = f"{self.base_url}/api/v1/scan"
        data = {
            'hash': hash_value,
            're_scan': '1' if rescan else '0'
        }
        headers = {
            **self.headers,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                return await response.json()
    
    async def get_scan_logs(self, hash_value: str) -> Dict[str, Any]:
        """
        获取特定文件的扫描日志
        
        Args:
            hash_value (str): 要获取日志的文件哈希值
        
        Returns:
            Dict[str, Any]: 扫描日志
        """
        url = f"{self.base_url}/api/v1/scan_logs"
        data = {
            'hash': hash_value
        }
        headers = {
            **self.headers,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                return await response.json()
    
    async def generate_json_report(self, hash_value: str) -> Dict[str, Any]:
        """
        为扫描过的文件生成详细的 JSON 报告
        
        Args:
            hash_value (str): 要生成报告的文件哈希值
        
        Returns:
            Dict[str, Any]: 详细的 JSON 报告
        """
        url = f"{self.base_url}/api/v1/report_json"
        data = {
            'hash': hash_value
        }
        headers = {
            **self.headers,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                return await response.json()
    
    async def get_recent_scans(self, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        """
        获取最近扫描列表
        
        Args:
            page (int, optional): 分页页码
            page_size (int, optional): 每页项目数
        
        Returns:
            Dict[str, Any]: 最近扫描列表
        """
        url = f"{self.base_url}/api/v1/scans"
        params = {
            'page': page,
            'page_size': page_size
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers, params=params) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"MobSF API Error: {response.status} - {error_text}")
                return await response.json()


# 创建 MobSF 客户端
mobsf_client = MobSFClient(BASE_URL, API_KEY)

# 创建服务器实例
server = McpServer(name="mobsf", version="1.0.0")


@server.tool(
    name="scanFile",
    description="Scan a file that has already been uploaded to MobSF. This tool analyzes the uploaded mobile application for security vulnerabilities and provides a comprehensive security assessment report.",
    params=as_params(
        hash=StringParam(
            description="Hash of the file to scan"
        ),
        reScan=BooleanParam(
            description="Set to true to force a rescan of the file",
            required=False,
            default=False
        )
    )
)
async def scan_file(hash: str, reScan: bool = False) -> ResponseContent:
    """
    扫描已上传到 MobSF 的文件
    
    Args:
        hash (str): 要扫描的文件哈希值
        reScan (bool, optional): 是否强制重新扫描
    
    Returns:
        ResponseContent: 扫描结果
    """
    try:
        result = await mobsf_client.scan_file(hash, reScan)
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
    except Exception as e:
        raise Exception(f"Error scanning file: {str(e)}")


@server.tool(
    name="uploadFile",
    description="Upload a mobile application file (APK, IPA, or APPX) to MobSF for security analysis. This is the first step before scanning and must be done prior to using other analysis functions.",
    params=as_params(
        file=StringParam(
            description="Upload file path"
        )
    )
)
async def upload_file(file: str) -> ResponseContent:
    """
    上传文件到 MobSF 进行分析
    
    Args:
        file (str): 要上传的文件路径
    
    Returns:
        ResponseContent: 上传响应
    """
    try:
        result = await mobsf_client.upload_file(file)
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
    except Exception as e:
        raise Exception(f"Error uploading file: {str(e)}")


@server.tool(
    name="getScanLogs",
    description="Retrieve detailed scan logs for a previously analyzed mobile application using its hash value. These logs contain information about the scanning process and any issues encountered.",
    params=as_params(
        hash=StringParam(
            description="Hash file to getting scan logs"
        )
    )
)
async def get_scan_logs(hash: str) -> ResponseContent:
    """
    获取特定文件的扫描日志
    
    Args:
        hash (str): 要获取日志的文件哈希值
    
    Returns:
        ResponseContent: 扫描日志
    """
    try:
        result = await mobsf_client.get_scan_logs(hash)
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
    except Exception as e:
        raise Exception(f"Error getting scan logs: {str(e)}")


@server.tool(
    name="getJsonReport",
    description="Generate and retrieve a comprehensive security analysis report in JSON format for a scanned mobile application. This report includes detailed findings about security vulnerabilities, permissions, API calls, and other security-relevant information.",
    params=as_params(
        hash=StringParam(
            description="Hash file to getting scan logs"
        )
    )
)
async def get_json_report(hash: str) -> ResponseContent:
    """
    为扫描过的文件生成详细的 JSON 报告
    
    Args:
        hash (str): 要生成报告的文件哈希值
    
    Returns:
        ResponseContent: 详细的 JSON 报告
    """
    try:
        result = await mobsf_client.generate_json_report(hash)
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
    except Exception as e:
        raise Exception(f"Error generating JSON report: {str(e)}")


@server.tool(
    name="getRecentScans",
    description="Retrieve a list of recently performed security scans on the MobSF server, showing mobile applications that have been analyzed, their statuses, and basic scan information.",
    params=as_params(
        page=NumberParam(
            description="Page number for result",
            required=False,
            default=1
        ),
        pageSize=NumberParam(
            description="Page size for result",
            required=False,
            default=10
        )
    )
)
async def get_recent_scans(page: int = 1, pageSize: int = 10) -> ResponseContent:
    """
    获取最近扫描列表
    
    Args:
        page (int, optional): 分页页码
        pageSize (int, optional): 每页项目数
    
    Returns:
        ResponseContent: 最近扫描列表
    """
    try:
        result = await mobsf_client.get_recent_scans(page, pageSize)
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
    except Exception as e:
        raise Exception(f"Error getting recent scans: {str(e)}")


if __name__ == "__main__":
    server.run() 