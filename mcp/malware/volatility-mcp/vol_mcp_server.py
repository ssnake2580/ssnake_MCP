"""
Volatility MCP Server

A server that integrates Volatility memory analysis capabilities with MCP.

This server provides an interface between Volatility's memory analysis capabilities
and the MCP (Mission Control Protocol) framework, allowing remote memory analysis
operations through a standardized API.

Author:
    @Gaffx
"""

from mcp.server.fastmcp import FastMCP
import logging
import argparse
from typing import List, Optional
from http_client import HttpClient  

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VolatilityMCP:
    """
    A class that integrates Volatility memory analysis capabilities with MCP.
    
    This class provides tools for memory analysis through the Volatility API.
    """
    
    def __init__(self, mcp_name: str = "vol-mcp", vol_url: str = "http://localhost:8000"):
        """
        Initialize the VolatilityMCP server.
        
        Args:
            mcp_name: The name of the MCP server
            vol_url: The base URL of the Volatility API
        """
        self.mcp = FastMCP(mcp_name)
        self.vol_url = vol_url
        self.memory_image_path = None
        
        # Register tools with MCP
        self._register_tools()
        
    def _register_tools(self) -> None:
        """Register all available tools with the MCP server."""
        self.mcp.tool()(self.get_processes)
        self.mcp.tool()(self.get_connections)
        self.mcp.tool()(self.get_cmdline)
    
    def set_memory_image(self, image_path: str) -> None:
        """
        Set the memory image path to use for analysis.
        
        Args:
            image_path: Path to the memory image file
        """
        self.memory_image_path = image_path
        logger.info(f"Memory image path set to: {self.memory_image_path}")
    
    def get_processes(self) -> List[str]:
        """
        Retrieve process information from the volatility analysis server.
        
        Returns:
            List of process information strings
        """
        return HttpClient.http_get(
            self.vol_url, 
            "analyze/process", 
            params={"image_path": self.memory_image_path}
        )
    
    def get_connections(self) -> List[str]:
        """
        Retrieve network connection information from the volatility analysis server.
        
        Returns:
            List of network connection information strings
        """
        return HttpClient.http_get(
            self.vol_url, 
            "analyze/connection", 
            params={"image_path": self.memory_image_path}
        )
    
    def get_cmdline(self) -> List[str]:
        """
        Retrieve command line information from the volatility analysis server.
        
        Returns:
            List of command line information strings
        """
        return HttpClient.http_get(
            self.vol_url, 
            "analyze/cmdline", 
            params={"image_path": self.memory_image_path}
        )
    
    def run(self) -> None:
        """Run the MCP server."""
        self.mcp.run()


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(description='Volatility MCP Server')
    parser.add_argument('--image', '-i', dest='image_path', 
                        help='Path to the memory image file')
    parser.add_argument('--url', '-u', dest='vol_url',
                        default="http://localhost:8000",
                        help='URL of the Volatility API (default: http://localhost:8000)')
    
    return parser.parse_args()


if __name__ == "__main__":
    # Parse arguments
    args = parse_arguments()
    
    # Create and configure the VolatilityMCP instance
    vol_mcp = VolatilityMCP(vol_url=args.vol_url)
    
    # Set memory image path if provided
    if args.image_path:
        vol_mcp.set_memory_image(args.image_path)
    
    # Run the MCP server
    vol_mcp.run()



