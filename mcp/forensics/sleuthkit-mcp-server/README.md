# The Sleuth Kit MCP Server

The Sleuth Kit MCP Server는 [Sleuth Kit](https://www.sleuthkit.org/) CLI 도구(`mmstat`, `mmls`, `fls`, `ifind`, `icat`)를 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 서버 형태로 노출합니다. 이를 통해 Cursor, Claude Desktop 등 MCP 클라이언트에서 **파일시스템 이미지(E01, RAW, VMDK 등)** 를 분석하고 파일을 추출할 수 있습니다.

## Tools

- `sleuthkit_healthcheck` : Sleuth Kit 바이너리 설치 상태 점검
- `disk_info` : file 명령어와 mmstat으로 디스크 이미지 파일 정보 확인  
- `disk_partition_info` : mmls로 디스크 파티션 정보 분석 
- `search_inode_by_path` : ifind로 메인 파티션 오프셋을 기준으로 직접 경로 탐색을 통해 해당 폴더의 inode 번호 확인  
- `files_in_directory` : fls로 폴더의 내용 확인  
- `extract_files_by_inode` : icat으로 inode 번호를 활용한 파일 추출  
- `extract_directory_tree_by_inode` : icat으로 원본 경로 구조를 유지하며 inode 번호를 활용한 파일 추출  
- `istat_metadata` : istat으로 디스크 이미지에서 inode를 기반으로 해당 파일들의 메타 정보 확인

## Installation

### 1. Python 환경 준비
```bash
git clone https://github.com/heejung0/sleuthkit-mcp-server.git
cd sleuthkit-mcp-server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
- Windows의 경우 python-magic-bin 추가 설치

### 2. Sleuth Kit 설치
- MacOS (Homebrew)
    ```bash
    brew install sleuthkit
    ````

- Linux
    ```bash
    sudo apt update
    sudo apt install sleuthkit
    ```

- Windows : [해당 링크](https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-4.14.0-win32.zip)에서 Windows Binary 다운로드


### 3. MCP Client 연결
- MacOS
```json
{
  "mcpServers": {
    "sleuthkit-MCP": {
      "command": "/path/to/.venv/bin/python",
      "args": [
        "/path/to/sleuthkit_mcp_server.py"
      ],
      "env": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

- Windows
```json
{
  "mcpServers": {
    "sleuthkit-MCP": {
      "command": "/path/to/.venv/Scripts/python",
      "args": [
        "/path/to/sleuthkit_mcp_server.py"
      ],
      "env": {
        "PATH": "/path/to/sleuthkit/bin"
      }
    }
  }
}
```
