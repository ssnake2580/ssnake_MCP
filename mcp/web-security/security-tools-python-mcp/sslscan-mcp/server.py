#!/usr/bin/env python3
"""
SSLScan MCP Server
A Model Context Protocol server that provides SSLScan functionality for SSL/TLS security scanning.
"""

import sys
import subprocess
import asyncio
from typing import List
from mcp.server.fastmcp import FastMCP

# Check if sslscan binary is provided
if len(sys.argv) < 2:
    print("Usage: python server.py <sslscan binary>", file=sys.stderr)
    sys.exit(1)

sslscan_command = sys.argv[1]

# Create FastMCP server instance
mcp = FastMCP("sslscan", version="1.0.0")

@mcp.tool()
async def do_sslscan(target: str, sslscan_args: List[str] = None) -> str:
    """Execute SSLScan, a comprehensive SSL/TLS scanner that identifies supported cipher suites, SSL/TLS versions, certificate information, and security vulnerabilities in SSL/TLS configurations of web servers and other services. It helps security professionals assess the security posture of SSL/TLS implementations.
    
    Args:
        target: Target URL to scan (must begin with https:// for proper SSL/TLS scanning)
        sslscan_args: Additional SSLScan arguments
        --sni-name=<name>    Hostname for SNI
  --ipv4, -4           Only use IPv4
  --ipv6, -6           Only use IPv6

  --show-certificate   Show full certificate information
  --show-certificates  Show chain full certificates information
  --show-client-cas    Show trusted CAs for TLS client auth
  --no-check-certificate  Don't warn about weak certificate algorithm or keys
  --ocsp               Request OCSP response from server
  --pk=<file>          A file containing the private key or a PKCS#12 file
                       containing a private key/certificate pair
  --pkpass=<password>  The password for the private  key or PKCS#12 file
  --certs=<file>       A file containing PEM/ASN1 formatted client certificates

  --ssl2               Only check if SSLv2 is enabled
  --ssl3               Only check if SSLv3 is enabled
  --tls10              Only check TLSv1.0 ciphers
  --tls11              Only check TLSv1.1 ciphers
  --tls12              Only check TLSv1.2 ciphers
  --tls13              Only check TLSv1.3 ciphers
  --tlsall             Only check TLS ciphers (all versions)
  --show-ciphers       Show supported client ciphers
  --show-cipher-ids    Show cipher ids
  --iana-names         Use IANA/RFC cipher names rather than OpenSSL ones
  --show-times         Show handhake times in milliseconds

  --no-cipher-details  Disable EC curve names and EDH/RSA key lengths output
  --no-ciphersuites    Do not check for supported ciphersuites
  --no-compression     Do not check for TLS compression (CRIME)
  --no-fallback        Do not check for TLS Fallback SCSV
  --no-groups          Do not enumerate key exchange groups
  --no-heartbleed      Do not check for OpenSSL Heartbleed (CVE-2014-0160)
  --no-renegotiation   Do not check for TLS renegotiation
  --show-sigs          Enumerate signature algorithms

  --starttls-ftp       STARTTLS setup for FTP
  --starttls-imap      STARTTLS setup for IMAP
  --starttls-irc       STARTTLS setup for IRC
  --starttls-ldap      STARTTLS setup for LDAP
  --starttls-mysql     STARTTLS setup for MYSQL
  --starttls-pop3      STARTTLS setup for POP3
  --starttls-psql      STARTTLS setup for PostgreSQL
  --starttls-smtp      STARTTLS setup for SMTP
  --starttls-xmpp      STARTTLS setup for XMPP
  --xmpp-server        Use a server-to-server XMPP handshake
  --rdp                Send RDP preamble before starting scan

  --bugs               Enable SSL implementation bug work-arounds
  --no-colour          Disable coloured output
  --sleep=<msec>       Pause between connection request. Default is disabled
  --timeout=<sec>      Set socket timeout. Default is 3s
  --connect-timeout=<sec>  Set connect timeout. Default is 75s
  --verbose            Display verbose output
  --version            Display the program version
  --xml=<file>         Output results to an XML file. Use - for STDOUT.
  
    Returns:
        Results from SSLScan SSL/TLS security assessment
    """
    if sslscan_args is None:
        sslscan_args = []
    
    try:
        # Construct the command - args first, then target
        cmd = [sslscan_command] + sslscan_args + [target]
        
        # Execute sslscan command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            text=True
        )
        
        # Wait for completion and get output
        stdout, _ = await process.communicate()
        
        if process.returncode == 0:
            return stdout + "\n sslscan completed successfully"
        else:
            return f"sslscan exited with code {process.returncode}\nOutput:\n{stdout}"
            
    except Exception as e:
        return f"Failed to start sslscan: {str(e)}"

if __name__ == "__main__":
    mcp.run() 