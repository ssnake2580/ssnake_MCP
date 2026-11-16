"""Helper utilities for making HTTP requests to the Volatility API.

This module provides functions for making HTTP requests to the Volatility API
with error handling and response processing.
"""

import requests
import logging
from typing import List, Dict, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class HttpClient:
    """
    Handle HTTP requests with built-in error handling.
    
    Args:
        timeout: Request timeout in seconds, defaults to DEFAULT_TIMEOUT
    """
    
    DEFAULT_TIMEOUT = 30
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize HTTP client with specified timeout.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
    
    @staticmethod
    def _handle_request_error(e: Exception) -> List[str]:
        """
        Handle exceptions during HTTP requests and return error message.
        
        Args:
            e: Exception that occurred during request
            
        Returns:
            List[str]: List containing error message
        """
        error_msg = f"Request failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [error_msg]
    
    @staticmethod
    def _process_response(response: requests.Response) -> List[str]:
        """
        Process HTTP response and extract content as list of strings.
        
        Args:
            response: Response object from requests
            
        Returns:
            List[str]: Response content split into lines
        """
        response.encoding = 'utf-8'
        logger.info(f"Response status: {response.status_code}")
        
        if not response.ok:
            error_msg = f"Error {response.status_code}: {response.text.strip()}"
            logger.error(error_msg)
            return [error_msg]
        
        # Try to parse as JSON
        try:
            json_data = response.json()
            # For text-based responses in JSON, extract and return as lines
            if isinstance(json_data, dict) and any(isinstance(v, str) and '\n' in v for v in json_data.values()):
                # Find the first string value that contains newlines and return it split
                for value in json_data.values():
                    if isinstance(value, str) and '\n' in value:
                        return value.splitlines()
            
            # Otherwise return the JSON as a single-item list
            return [str(json_data)]
        except ValueError:
            # Not JSON, return text
            return response.text.splitlines()
    
    def _execute_request(self, url: str, method: str, params: Dict[str, Any], data: Optional[Dict[str, Any]]) -> List[str]:
        """
        Execute HTTP request with given parameters and return response content.
        
        Args:
            url: Full URL for the request
            method: HTTP method to use
            params: Query parameters for the request
            data: Body data for POST requests
            
        Returns:
            List[str]: Response content split into lines
            
        Raises:
            Exception: If request fails or receives invalid response
        """
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=params, timeout=self.timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, params=params, timeout=self.timeout)
            else:
                return [f"Unsupported HTTP method: {method}"]
            
            return self._process_response(response)
        except Exception as e:
            return self._handle_request_error(e)
    
    def request(self, base_url: str, endpoint: str, method: str = "GET",
               params: Optional[Dict[str, Any]] = None,
               data: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Perform an HTTP request with error handling.
        
        Args:
            base_url: Base URL of the API
            endpoint: API endpoint to call
            method: HTTP method (GET, POST, etc.)
            params: Query parameters for requests
            data: Body data for POST requests
            
        Returns:
            List[str]: Response content split into lines
            
        Raises:
            Exception: If request fails or receives invalid response
        """
        params = params or {}
        url = f"{base_url}/{endpoint}"
        
        logger.info(f"Making {method} request to: {url}")
        return self._execute_request(url, method, params, data)
    
    def get(self, base_url: str, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Perform a GET request using instance method.
        
        Args:
            base_url: Base URL of the API
            endpoint: API endpoint to call
            params: Query parameters for the request
            
        Returns:
            List[str]: Response content split into lines
        """
        return self.request(base_url, endpoint, method="GET", params=params)
    
    @staticmethod
    def http_get(base_url: str, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Perform a GET request using a new client instance.
        
        Args:
            base_url: Base URL of the API
            endpoint: API endpoint to call
            params: Query parameters for the request
            
        Returns:
            List[str]: Response content split into lines
        """
        client = HttpClient()
        return client.get(base_url, endpoint, params=params)
    
    @staticmethod
    def http_post(base_url: str, endpoint: str, data: Optional[Dict[str, Any]] = None,
                params: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Perform a POST request using a new client instance.
        
        Args:
            base_url: Base URL of the API
            endpoint: API endpoint to call
            data: Body data for POST request
            params: Query parameters for the request
            
        Returns:
            List[str]: Response content split into lines
        """
        client = HttpClient()
        return client.request(base_url, endpoint, method="POST", params=params, data=data)
