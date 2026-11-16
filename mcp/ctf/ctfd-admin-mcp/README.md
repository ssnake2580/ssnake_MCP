# CTFd Admin MCP

An MCP (Model Context Protocol) server that exposes CTFd admin operations as tools, enabling an AI agent to generate and deploy an entire CTF competition's worth of challenges programmatically.

## Features

### Challenges
- List, create, update, and delete challenges
- Supports both **standard** (fixed points) and **dynamic** (decaying points) challenge types
- Control visibility (`hidden` / `visible`) independently of creation, so you can build everything out before players see it
- Set optional connection info (e.g. netcat address) and max attempt limits

### Flags
- Attach one or more flags to any challenge
- `static` (exact match) and `regex` flag types
- Optional case-insensitive matching for static flags

### Hints
- Add hints with configurable point costs
- Hints are locked until a player chooses to spend points to reveal them

### Files
- Upload files and attach them to challenges via base64-encoded content
- List and delete uploaded files

### Tags & Topics
- Tag challenges with arbitrary labels (e.g. `beginner`, `sql-injection`)
- Associate challenges with topics for grouping

### Users & Teams
- Create, update, and delete user and team accounts
- Set admin vs. player roles, pre-verify accounts, hide from or ban from the scoreboard

### Solutions
- Create official write-ups / walkthroughs and attach them to challenges
- Three visibility states: `"hidden"` (default, not shown to anyone), `"visible"` (public), or `"solved"` (shown only to players who have solved the challenge)
- Update or delete solutions at any time

### Scoreboard & Submissions
- Read current standings
- Browse flag submission history, filterable by challenge or user

### Configuration
- Read and update all CTFd instance settings: competition name, description, start/end times, freeze time, registration and visibility modes

### Bulk / Convenience Tools
- **`create_full_challenge`** — creates a challenge together with all its flags, hints, and tags in a single tool call (the primary tool for agent-driven competition generation)
- **`publish_challenge`** — flip a single challenge from hidden to visible
- **`publish_all_challenges`** — make every hidden challenge visible at once when the competition is ready to launch

---

## Requirements

- Python 3.10+
- A running CTFd instance
- A CTFd **admin** API token (Settings → Access Tokens inside CTFd)

---

## Installation

```bash
git clone https://github.com/jselliott/CTFd-Admin-MCP.git
cd CTFd-Admin-MCP
pip install -r requirements.txt
```

---

## Running the server

The server uses **stdio transport** and is intended to be launched by an MCP host (Claude Desktop, Claude Code, or any MCP-compatible agent runtime).

```bash
python server.py --url https://your-ctfd-instance.com --token <admin-api-token>
```

| Argument | Description |
|---|---|
| `--url` | Base URL of the CTFd instance (no trailing slash) |
| `--token` | Admin API token from CTFd Settings → Access Tokens |

---

## Deployment with Claude Desktop

Add the following to your Claude Desktop MCP configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ctfd-admin": {
      "command": "python3",
      "args": [
        "/absolute/path/to/ctfd-admin-mcp/server.py",
        "--url", "https://your-ctfd-instance.com",
        "--token", "your-admin-api-token"
      ]
    }
  }
}
```

Restart Claude Desktop after saving. The CTFd admin tools will appear in the tool list.

---

## Deployment with Claude Code

Add the server to your project or global Claude Code MCP settings:

```bash
# Project-level (stored in .claude/settings.json)
claude mcp add ctfd-admin -- python3 /absolute/path/to/server.py \
  --url https://your-ctfd-instance.com \
  --token your-admin-api-token
```

Or edit `.claude/settings.json` directly:

```json
{
  "mcpServers": {
    "ctfd-admin": {
      "command": "python3",
      "args": [
        "/absolute/path/to/ctfd-admin-mcp/server.py",
        "--url", "https://your-ctfd-instance.com",
        "--token", "your-admin-api-token"
      ]
    }
  }
}
```

---

## Usage: Generating a full competition

Once connected, prompt the agent to build challenges. The key tool is `create_full_challenge`, which handles challenge creation, flags, hints, and tags in one call.

Example prompt:

> Generate a 10-challenge beginner CTF covering web, crypto, and forensics categories. Use the CTFd tools to create all the challenges in hidden state, then publish them all when done.

The agent will call `create_full_challenge` for each challenge and `publish_all_challenges` at the end.

### Typical workflow

1. **Configure the competition** — `update_configs` to set the name, description, and start/end times
2. **Create challenges** — `create_full_challenge` for each one (created hidden by default)
3. **Upload files** — `upload_file_b64` for any challenge with attachments
4. **Review** — `list_challenges` to verify everything looks right
5. **Publish** — `publish_all_challenges` to make them visible to players

---

## Tool reference

| Tool | Description |
|---|---|
| `list_challenges` | List challenges, with optional filters |
| `get_challenge` | Get a single challenge by ID |
| `create_challenge` | Create a challenge |
| `update_challenge` | Edit challenge fields |
| `delete_challenge` | Delete a challenge and all associated data |
| `get_challenge_types` | List installed challenge type plugins |
| `list_flags` | List flags (optionally for one challenge) |
| `create_flag` | Add a flag to a challenge |
| `update_flag` | Edit a flag |
| `delete_flag` | Delete a flag |
| `list_hints` | List hints (optionally for one challenge) |
| `create_hint` | Add a hint to a challenge |
| `update_hint` | Edit a hint |
| `delete_hint` | Delete a hint |
| `list_files` | List uploaded files |
| `upload_file_b64` | Upload a file (base64-encoded) and attach to a challenge |
| `delete_file` | Delete an uploaded file |
| `list_tags` | List tags |
| `create_tag` | Add a tag to a challenge |
| `delete_tag` | Delete a tag |
| `list_topics` | List topics |
| `create_topic` | Add a topic to a challenge |
| `delete_topic` | Delete a topic |
| `list_users` | List user accounts |
| `get_user` | Get a user by ID |
| `create_user` | Create a user account |
| `update_user` | Edit a user account |
| `delete_user` | Delete a user account |
| `list_teams` | List teams |
| `get_team` | Get a team by ID |
| `create_team` | Create a team |
| `delete_team` | Delete a team |
| `list_solutions` | List solutions/write-ups, with optional filters |
| `get_solution` | Get a single solution by ID |
| `create_solution` | Create a solution/write-up for a challenge |
| `update_solution` | Edit a solution's content or state |
| `delete_solution` | Delete a solution |
| `get_scoreboard` | Get current standings |
| `list_submissions` | Browse flag submission history |
| `get_configs` | Read CTFd instance configuration |
| `update_configs` | Update CTFd instance configuration |
| `create_full_challenge` | Create a challenge + flags + hints + tags in one call |
| `publish_challenge` | Make a hidden challenge visible |
| `publish_all_challenges` | Make all hidden challenges visible |
