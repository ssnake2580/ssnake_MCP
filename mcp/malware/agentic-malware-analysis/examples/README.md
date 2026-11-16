# Example Samples

This directory contains malware samples used in the companion blog post [Building a Pipeline for Agentic Malware Analysis][blog-post].

Samples are distributed as a single password-protected zip archive (standard practice for malware samples):

| Archive | Password |
|---------|----------|
| `samples.zip` | `infected` |

To extract:

```bash
cd examples
unzip -P infected samples.zip
```

This creates a `samples/` directory with the unpacked files.

## mfc42ul.dll

`mfc42ul.dll` is a DLL from the German "Staatstrojaner" (federal Trojan horse) case, publicized by the [Chaos Computer Club (CCC)][staatstrojaner] in 2011. It is a good test case for agentic analysis because it has a mix of easily discoverable and deeply hidden functionality:

**Easy to identify** from strings, imports, and a shallow code pass:
- Screenshot capture
- Skype VoIP interception
- Persistence mechanisms
- Proxy-aware outbound communication

**Harder to recover** without deeper analysis:
- Process-aware activation logic (DllMain → orchestrator chain)
- Internal command dispatch table
- C2 protocol details (protocol marker `C3PO-r2d2-POE`, wire format, vtable-based send/receive)
- Statically embedded AES-128 key and encryption/decryption routines
- Hardcoded C2 server information

| Property | Value |
|----------|-------|
| SHA-256 | `be36ce1e79ba6f97038a6f9198057abecf84b38f0ebb7aaa897fd5cf385d702f` |
| MD5 | `930712416770a8d5e6951f3e38548691` |
| Format | PE DLL (32-bit) |

To analyze inside the Docker environment:

```bash
# 1. Launch the container
./run_docker.sh

# 2. Extract the samples
cd examples && unzip -P infected samples.zip && cd ..

# 3. Start Claude Code or Codex
claude   # or: codex

# 4. Prompt the agent
# Analyze the malware in examples/samples/mfc42ul.dll -- Give me a detailed
# overview of the sample's functionality and features, together with the
# corresponding code locations. Use the skill
# /agent/agent_helpers/claude/skills/malware-analysis-orchestrator/ for
# analysis.
```

[blog-post]: https://synthesis.to/2026/03/18/agentic_malware_analysis.html
[staatstrojaner]: https://www.ccc.de/en/updates/2011/staatstrojaner
