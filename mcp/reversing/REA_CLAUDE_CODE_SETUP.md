# REA 설치 및 Claude Code 연동 정리

> 환경: WSL Ubuntu 24.04 (x86_64) / 사용자 `kimmc` / 2026-11-13 작업 로그 기준

## 1. 작업 목표와 결과

WSL 환경에서 REA(Reverse Engineering Assistant) MCP를 구성하고 Claude Code에서 **Ghidra, JADX, Kuna** 분석 엔진을 사용할 수 있도록 설정했다.

- **REA MCP 6.8.0**: Claude Code에 등록 및 연결 확인
- **Ghidra 12.1.4**: 설치 및 headless 분석 환경 진단 정상
- **JADX 1.5.6 / JADX Headless MCP 0.7.1**: 설치, JAR 해시 검증, REA 진단 정상
- **Kuna 1.990**: 설치, REA 진단 및 Claude Code 등록 정상
- **Rizin 0.10.0, Radare2 6.2.7, GDB 15.1, LLDB 18.1.3**: 별도 설치 확인
- **IDA**: 사용하지 않기로 결정
- **Hopper**: 배포 서버 연결 문제로 설치 보류

> **검증 범위:** 설치·환경 설정·MCP 등록은 확인했다. Kuna를 이용한 실제 ELF 분석 및 JADX를 이용한 실제 APK 분석의 성공 로그는 아직 확보되지 않았다.

## 2. 주요 경로

| 항목 | 경로 |
| --- | --- |
| REA 프로젝트 | `/home/kimmc/Projects/ssnake_MCP/mcp/reversing/rea` |
| REA 실행 스크립트 | `/home/kimmc/Projects/ssnake_MCP/mcp/reversing/rea/scripts/rea.mjs` |
| Claude Code 설정 | `/home/kimmc/.claude.json` |
| Node.js | `/home/kimmc/.nvm/versions/node/v24.22.3/bin/node` |
| Ghidra | `/home/kimmc/Tools/ghidra_12.1.4_PUBLIC` |
| Java | `/usr/lib/jvm/java-21-openjdk-amd64` |
| JADX CLI | `/home/kimmc/Tools/jadx/bin/jadx` |
| JADX MCP JAR | `/home/kimmc/.local/share/rea/android/jadx-headless-mcp-0.7.1-all.jar` |
| Kuna 실행 파일 | `/home/kimmc/Tools/kuna/kuna-v1.990-linux-x86_64/kuna` |
| Kuna 캐시 (첫 실행 시 생성) | `/home/kimmc/.cache/rea/kuna` |

## 3. JADX Headless MCP 설치

### 3.1 JAR 다운로드

```bash
mkdir -p ~/.local/share/rea/android
cd ~/.local/share/rea/android

curl -fL --retry 3 \
  -o jadx-headless-mcp-0.7.1-all.jar \
  https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar
```

### 3.2 SHA-256 검증

```bash
echo '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  jadx-headless-mcp-0.7.1-all.jar' \
  | sha256sum -c -
```

확인 결과:

```text
jadx-headless-mcp-0.7.1-all.jar: OK
```

### 3.3 환경변수 설정 및 진단

```bash
export REA_JADX_MCP_JAR="$HOME/.local/share/rea/android/jadx-headless-mcp-0.7.1-all.jar"
cd ~/Projects/ssnake_MCP/mcp/reversing/rea
node scripts/rea.mjs doctor --json > /tmp/rea-doctor.json
```

확인 결과: `jadx` → `ok: true`, `classification: healthy`. 단, 이 진단은 JAR와 설정을 확인하는 것이며 실제 APK 분석 및 메모리 적합성 검증은 아니다.

## 4. Kuna 1.990 설치

### 4.1 공식 릴리스 파일 확인

```bash
sudo apt install -y curl jq tar file
mkdir -p ~/Tools/kuna
cd ~/Tools/kuna

curl -fsSL \
  https://api.github.com/repos/Noelo-Lab/kuna/releases/tags/v1.990 \
  -o release.json
jq -r '.assets[].name' release.json
```

Linux x86_64 환경에 맞는 파일: `kuna-v1.990-linux-x86_64.tar.gz`.

### 4.2 다운로드 및 압축 해제

```bash
cd ~/Tools/kuna
curl -fL --retry 3 \
  -o kuna-v1.990-linux-x86_64.tar.gz \
  https://github.com/Noelo-Lab/kuna/releases/download/v1.990/kuna-v1.990-linux-x86_64.tar.gz

tar -xzf kuna-v1.990-linux-x86_64.tar.gz
find ~/Tools/kuna -type f -name kuna
```

실제 실행 파일은 최상위 `~/Tools/kuna/kuna`가 아니라 아래에 생성되었다.

```text
/home/kimmc/Tools/kuna/kuna-v1.990-linux-x86_64/kuna
```

### 4.3 실행 권한 및 버전 확인

```bash
chmod +x ~/Tools/kuna/kuna-v1.990-linux-x86_64/kuna
~/Tools/kuna/kuna-v1.990-linux-x86_64/kuna --version
```

출력:

```text
kuna 1.990
```

### 4.4 REA 연동 및 진단

```bash
export REA_KUNA_COMMAND="$HOME/Tools/kuna/kuna-v1.990-linux-x86_64/kuna"
cd ~/Projects/ssnake_MCP/mcp/reversing/rea
node scripts/rea.mjs doctor --provider kuna
```

진단 결과:

```text
healthy: true
kuna-installation: ok: true
kuna-cache: ok: true
```

진단 로그에 표시된 Kuna 실행 파일 SHA-256:

```text
169580f97fcd466cb05e0eb2cdba8d9fd02c80269f5bc4dde1179222a713cf43
```

> 주의: 터미널에서 `export`한 변수는 현재 셸에만 적용된다. Claude Code에서 지속적으로 사용하려면 REA의 클라이언트 등록에 환경변수를 기록해야 한다.

## 5. Claude Code에 REA MCP 등록

### 5.1 설정 미리보기

Ghidra, Java, JADX, Kuna 관련 환경변수가 현재 터미널에서 잡힌 상태로 다음을 실행했다.

```bash
cd ~/Projects/ssnake_MCP/mcp/reversing/rea
node scripts/rea.mjs setup --client claude_code --dry-run
```

미리보기에서 확인된 값:

```text
GHIDRA_INSTALL_DIR=/home/kimmc/Tools/ghidra_12.1.4_PUBLIC
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
REA_JADX_MCP_JAR=/home/kimmc/.local/share/rea/android/jadx-headless-mcp-0.7.1-all.jar
REA_KUNA_COMMAND=/home/kimmc/Tools/kuna/kuna-v1.990-linux-x86_64/kuna
```

### 5.2 설정 적용

```bash
node scripts/rea.mjs setup --client claude_code --skill=false
```

설치 화면에서 `Yes, apply` 선택. 기존 Claude Code 설정의 다른 항목은 보존되며, 설정 파일 백업 경로도 안내되었다.

적용 결과:

```text
Deep analysis: Ghidra, Jadx, and Kuna
Agent access: Claude Code
Guided reverse-engineering workflows: installed
Restart Claude Code to load REA.
```

### 5.3 최종 진단

```bash
node scripts/rea.mjs doctor --client claude_code --provider kuna
```

확인 결과:

```text
healthy: true
kuna-installation: ok: true
kuna-cache: ok: true
registration:claude_code: ok: true
```

즉, **Kuna 설치와 Claude Code 설정 등록까지 완료**되었다.

## 6. Claude Code MCP 연결 확인

```bash
claude mcp list
```

기존 출력에서 다음 MCP 서버들이 `Connected`로 확인되었다.

- `rea`
- `forensics-utils`
- `mem-forensics`
- `spoor-sift`
- `volpilot`

REA는 다음 명령으로 실행되도록 등록되어 있다.

```text
/home/kimmc/.nvm/versions/node/v24.22.3/bin/node
/home/kimmc/Projects/ssnake_MCP/mcp/reversing/rea/scripts/rea.mjs mcp
```

> REA의 초기 연결은 확인했지만, **Kuna 등록 변경 후 Claude Code를 재시작하고 실제 분석을 수행한 로그는 아직 없다.**

## 7. 남은 작업 및 참고사항

### 7.1 Claude Code 재시작 및 실제 ELF 분석 테스트

기존 Claude Code 세션을 종료한 뒤 새로 실행한다.

```bash
claude
```

Claude Code에 아래와 같이 요청한다.

```text
REA MCP의 Kuna 엔진으로 /bin/ls ELF 파일을 분석해 줘.
바이너리 아키텍처, 주요 함수, 문자열, 호출 관계를 확인하고
실제로 사용한 REA 도구와 분석 근거를 제시해 줘.
분석 실패 시 다른 엔진으로 자동 전환하지 말고 오류를 보고해 줘.
```

### 7.2 아직 구성하지 않은 항목

- **Hopper:** 다운로드 서버 접속 실패로 보류
- **IDA:** 사용하지 않기로 결정
- **Codex CLI / Copilot CLI:** REA 등록 진단에서 `missing` 표시. Claude Code 등록에는 영향 없음
- **REA 업데이트:** 로그상 6.8.0 사용 중이며 6.9.0 업데이트 안내가 표시됨. 업데이트는 아직 수행하지 않음

### 7.3 `environment_healthy: false` 해석

선택한 범위의 `doctor` 결과는 `healthy: true`였다. 동시에 전체 환경에 대해서는 `environment_healthy: false`가 표시되었으며, 로그에 Hopper·IDA 등 선택적 엔진 미구성과 다른 클라이언트 등록 누락이 보였다. **Kuna 자체의 설치나 Claude Code 등록 실패를 뜻하지 않는다.**

## 8. 빠른 재점검 명령어

```bash
cd ~/Projects/ssnake_MCP/mcp/reversing/rea

# 현재 터미널에서 Kuna 경로를 설정해야 provider 직접 진단이 가능할 수 있음
export REA_KUNA_COMMAND="$HOME/Tools/kuna/kuna-v1.990-linux-x86_64/kuna"

# Kuna + Claude Code 설정 상태
node scripts/rea.mjs doctor --client claude_code --provider kuna

# MCP 서버 연결 상태
claude mcp list

# 개별 실행 파일 버전
~/Tools/kuna/kuna-v1.990-linux-x86_64/kuna --version
jadx --version
```

---

**결론:** REA 6.8.0을 Claude Code에 연결하고 Ghidra 12.1.4, JADX Headless MCP 0.7.1, Kuna 1.990을 등록했다. 설치·설정 진단은 성공했으며, 실제 샘플 분석 검증이 다음 단계다.
