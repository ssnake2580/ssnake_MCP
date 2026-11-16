"""CTFd Admin MCP Server

Exposes CTFd admin operations as MCP tools so an AI agent can create and
manage entire CTF competitions programmatically.

Usage:
    python server.py --url https://ctf.example.com --token <admin-api-token>
"""

import argparse
import base64
import sys
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# CLI argument parsing (done before FastMCP is constructed so the globals are
# available when tool functions are defined)
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="CTFd Admin MCP Server")
parser.add_argument("--url", required=True, help="Base URL of the CTFd instance (e.g. https://ctf.example.com)")
parser.add_argument("--token", required=True, help="CTFd admin API token")
args, _ = parser.parse_known_args()

CTFD_URL = args.url.rstrip("/")
API_BASE = f"{CTFD_URL}/api/v1"
HEADERS = {
    "Authorization": f"Token {args.token}",
    "Content-Type": "application/json",
}

# ---------------------------------------------------------------------------
# Shared async HTTP client (created once per server lifetime)
# ---------------------------------------------------------------------------

_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(_app):
    global _client
    _client = httpx.AsyncClient(headers=HEADERS, timeout=30)
    try:
        yield {}
    finally:
        await _client.aclose()


def client() -> httpx.AsyncClient:
    if _client is None:
        raise RuntimeError("HTTP client not initialised — server not started yet")
    return _client


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _raise_for_status(resp: httpx.Response) -> dict:
    """Return parsed JSON or raise a descriptive error."""
    try:
        data = resp.json()
    except Exception:
        resp.raise_for_status()
        return {}
    if not resp.is_success:
        msg = data.get("message") or data.get("errors") or resp.text
        raise ValueError(f"CTFd API error {resp.status_code}: {msg}")
    return data


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="ctfd-admin",
    instructions=(
        "Tools for administering a CTFd instance. "
        "Use these to create challenges, flags, hints, files, tags, and manage users. "
        "Challenges must be created before flags/hints/files can be attached to them."
    ),
    lifespan=lifespan,
)

# ===========================================================================
# CHALLENGES
# ===========================================================================


@mcp.tool()
async def list_challenges(
    name: str = "",
    category: str = "",
    type: str = "",
    state: str = "",
) -> list[dict]:
    """List all challenges. Optionally filter by name, category, type, or state (visible/hidden)."""
    params: dict[str, Any] = {}
    if name:
        params["name"] = name
    if category:
        params["category"] = category
    if type:
        params["type"] = type
    if state:
        params["state"] = state
    resp = await client().get(f"{API_BASE}/challenges", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def get_challenge(challenge_id: int) -> dict:
    """Get full details for a single challenge by ID."""
    resp = await client().get(f"{API_BASE}/challenges/{challenge_id}")
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def create_challenge(
    name: str,
    category: str,
    description: str,
    value: int,
    type: str = "standard",
    state: str = "hidden",
    connection_info: str = "",
    max_attempts: int = 0,
    initial: int = 0,
    minimum: int = 0,
    decay: int = 0,
) -> dict:
    """Create a new challenge.

    Args:
        name: Challenge title.
        category: Category label (e.g. "Web", "Crypto", "Pwn").
        description: Challenge description / problem statement (HTML or plain text).
        value: Point value. For dynamic challenges set initial/minimum/decay instead.
        type: "standard" (default) or "dynamic" for decaying-value challenges.
        state: "hidden" (default, safe to build out before publishing) or "visible".
        connection_info: Optional service URL or netcat string shown to players.
        max_attempts: 0 means unlimited attempts.
        initial: Starting points for dynamic challenges (ignored for standard).
        minimum: Minimum points for dynamic challenges (ignored for standard).
        decay: Number of solves before reaching minimum (ignored for standard).
    """
    payload: dict[str, Any] = {
        "name": name,
        "category": category,
        "description": description,
        "state": state,
        "type": type,
    }
    if type == "dynamic":
        payload["initial"] = initial
        payload["minimum"] = minimum
        payload["decay"] = decay
    else:
        payload["value"] = value
    if connection_info:
        payload["connection_info"] = connection_info
    if max_attempts:
        payload["max_attempts"] = max_attempts

    resp = await client().post(f"{API_BASE}/challenges", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def update_challenge(
    challenge_id: int,
    name: str = "",
    category: str = "",
    description: str = "",
    value: int = 0,
    state: str = "",
    connection_info: str = "",
    max_attempts: int = -1,
) -> dict:
    """Update fields on an existing challenge. Only non-empty / non-zero arguments are sent."""
    payload: dict[str, Any] = {}
    if name:
        payload["name"] = name
    if category:
        payload["category"] = category
    if description:
        payload["description"] = description
    if value:
        payload["value"] = value
    if state:
        payload["state"] = state
    if connection_info:
        payload["connection_info"] = connection_info
    if max_attempts >= 0:
        payload["max_attempts"] = max_attempts
    if not payload:
        raise ValueError("No fields provided to update")
    resp = await client().patch(f"{API_BASE}/challenges/{challenge_id}", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_challenge(challenge_id: int) -> dict:
    """Permanently delete a challenge and all its associated flags, hints, and files."""
    resp = await client().delete(f"{API_BASE}/challenges/{challenge_id}")
    return _raise_for_status(resp)


@mcp.tool()
async def get_challenge_types() -> dict:
    """Return the list of installed challenge type plugins (e.g. standard, dynamic)."""
    resp = await client().get(f"{API_BASE}/challenges/types")
    return _raise_for_status(resp).get("data", {})


# ===========================================================================
# FLAGS
# ===========================================================================


@mcp.tool()
async def list_flags(challenge_id: int = 0) -> list[dict]:
    """List flags. If challenge_id is given, only flags for that challenge are returned."""
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    resp = await client().get(f"{API_BASE}/flags", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def create_flag(
    challenge_id: int,
    content: str,
    type: str = "static",
    data: str = "",
) -> dict:
    """Add a flag to a challenge.

    Args:
        challenge_id: ID of the challenge this flag belongs to.
        content: The flag string (e.g. "CTF{s0me_flag}").
        type: "static" (exact match, default) or "regex" (regex match).
        data: For static flags, "case_insensitive" to ignore case; leave empty for case-sensitive.
    """
    payload: dict[str, Any] = {
        "challenge_id": challenge_id,
        "content": content,
        "type": type,
    }
    if data:
        payload["data"] = data
    resp = await client().post(f"{API_BASE}/flags", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def update_flag(
    flag_id: int,
    content: str = "",
    type: str = "",
    data: str = "",
) -> dict:
    """Update a flag's content, type, or data."""
    payload: dict[str, Any] = {}
    if content:
        payload["content"] = content
    if type:
        payload["type"] = type
    if data:
        payload["data"] = data
    if not payload:
        raise ValueError("No fields provided to update")
    resp = await client().patch(f"{API_BASE}/flags/{flag_id}", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_flag(flag_id: int) -> dict:
    """Delete a flag by ID."""
    resp = await client().delete(f"{API_BASE}/flags/{flag_id}")
    return _raise_for_status(resp)


# ===========================================================================
# HINTS
# ===========================================================================


@mcp.tool()
async def list_hints(challenge_id: int = 0) -> list[dict]:
    """List hints. Optionally filter by challenge_id."""
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    resp = await client().get(f"{API_BASE}/hints", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def create_hint(
    challenge_id: int,
    content: str,
    cost: int = 0,
) -> dict:
    """Add a hint to a challenge.

    Args:
        challenge_id: Challenge this hint belongs to.
        content: The hint text shown to players after they unlock it.
        cost: Points deducted when a player unlocks the hint (0 = free).
    """
    payload = {
        "challenge_id": challenge_id,
        "content": content,
        "cost": cost,
    }
    resp = await client().post(f"{API_BASE}/hints", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def update_hint(
    hint_id: int,
    content: str = "",
    cost: int = -1,
) -> dict:
    """Update a hint's content or cost."""
    payload: dict[str, Any] = {}
    if content:
        payload["content"] = content
    if cost >= 0:
        payload["cost"] = cost
    if not payload:
        raise ValueError("No fields provided to update")
    resp = await client().patch(f"{API_BASE}/hints/{hint_id}", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_hint(hint_id: int) -> dict:
    """Delete a hint by ID."""
    resp = await client().delete(f"{API_BASE}/hints/{hint_id}")
    return _raise_for_status(resp)


# ===========================================================================
# FILES
# ===========================================================================


@mcp.tool()
async def list_files(challenge_id: int = 0) -> list[dict]:
    """List uploaded files. Optionally filter by challenge_id."""
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    resp = await client().get(f"{API_BASE}/files", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def upload_file_b64(
    challenge_id: int,
    filename: str,
    content_b64: str,
    mime_type: str = "application/octet-stream",
) -> dict:
    """Upload a file and attach it to a challenge.

    The file contents must be supplied as a base64-encoded string so that
    binary data can be passed through the JSON tool interface.

    Args:
        challenge_id: Challenge to attach the file to.
        filename: Name to store the file under (e.g. "challenge.zip").
        content_b64: Base64-encoded file contents.
        mime_type: MIME type of the file (default: application/octet-stream).
    """
    file_bytes = base64.b64decode(content_b64)
    # File uploads use multipart form-data; strip the JSON Content-Type header.
    upload_headers = {k: v for k, v in HEADERS.items() if k != "Content-Type"}
    files = {"file": (filename, file_bytes, mime_type)}
    data = {"challenge_id": challenge_id, "type": "challenge"}
    resp = await client().post(
        f"{API_BASE}/files",
        headers=upload_headers,
        files=files,
        data=data,
    )
    return _raise_for_status(resp).get("data", [{}])[0]


@mcp.tool()
async def delete_file(file_id: int) -> dict:
    """Delete an uploaded file by ID."""
    resp = await client().delete(f"{API_BASE}/files/{file_id}")
    return _raise_for_status(resp)


# ===========================================================================
# TAGS
# ===========================================================================


@mcp.tool()
async def list_tags(challenge_id: int = 0) -> list[dict]:
    """List tags. Optionally filter by challenge_id."""
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    resp = await client().get(f"{API_BASE}/tags", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def create_tag(challenge_id: int, value: str) -> dict:
    """Add a tag to a challenge (e.g. "beginner", "sql-injection")."""
    payload = {"challenge_id": challenge_id, "value": value}
    resp = await client().post(f"{API_BASE}/tags", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_tag(tag_id: int) -> dict:
    """Delete a tag by ID."""
    resp = await client().delete(f"{API_BASE}/tags/{tag_id}")
    return _raise_for_status(resp)


# ===========================================================================
# TOPICS
# ===========================================================================


@mcp.tool()
async def list_topics(challenge_id: int = 0) -> list[dict]:
    """List topics. Optionally filter by challenge_id."""
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    resp = await client().get(f"{API_BASE}/topics", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def create_topic(challenge_id: int, value: str, type: str = "challenge") -> dict:
    """Add a topic to a challenge."""
    payload = {"challenge_id": challenge_id, "value": value, "type": type}
    resp = await client().post(f"{API_BASE}/topics", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_topic(topic_id: int) -> dict:
    """Delete a topic by ID."""
    resp = await client().delete(f"{API_BASE}/topics/{topic_id}")
    return _raise_for_status(resp)


# ===========================================================================
# USERS
# ===========================================================================


@mcp.tool()
async def list_users(
    affiliation: str = "",
    country: str = "",
    bracket: str = "",
    banned: bool = False,
    hidden: bool = False,
) -> list[dict]:
    """List all registered users."""
    params: dict[str, Any] = {}
    if affiliation:
        params["affiliation"] = affiliation
    if country:
        params["country"] = country
    if bracket:
        params["bracket"] = bracket
    if banned:
        params["banned"] = "true"
    if hidden:
        params["hidden"] = "true"
    resp = await client().get(f"{API_BASE}/users", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def get_user(user_id: int) -> dict:
    """Get full details for a user by ID."""
    resp = await client().get(f"{API_BASE}/users/{user_id}")
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def create_user(
    name: str,
    email: str,
    password: str,
    type: str = "user",
    verified: bool = True,
    hidden: bool = False,
    banned: bool = False,
) -> dict:
    """Create a new user account.

    Args:
        name: Username.
        email: Email address.
        password: Initial password.
        type: "user" or "admin".
        verified: Whether the account is pre-verified (default True).
        hidden: Hide from scoreboard (default False).
        banned: Ban immediately (default False).
    """
    payload = {
        "name": name,
        "email": email,
        "password": password,
        "type": type,
        "verified": verified,
        "hidden": hidden,
        "banned": banned,
    }
    resp = await client().post(f"{API_BASE}/users", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def update_user(
    user_id: int,
    name: str = "",
    email: str = "",
    password: str = "",
    type: str = "",
    verified: bool | None = None,
    hidden: bool | None = None,
    banned: bool | None = None,
) -> dict:
    """Update a user account. Only provided (non-empty/non-None) fields are changed."""
    payload: dict[str, Any] = {}
    if name:
        payload["name"] = name
    if email:
        payload["email"] = email
    if password:
        payload["password"] = password
    if type:
        payload["type"] = type
    if verified is not None:
        payload["verified"] = verified
    if hidden is not None:
        payload["hidden"] = hidden
    if banned is not None:
        payload["banned"] = banned
    if not payload:
        raise ValueError("No fields provided to update")
    resp = await client().patch(f"{API_BASE}/users/{user_id}", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_user(user_id: int) -> dict:
    """Delete a user account by ID."""
    resp = await client().delete(f"{API_BASE}/users/{user_id}")
    return _raise_for_status(resp)


# ===========================================================================
# TEAMS
# ===========================================================================


@mcp.tool()
async def list_teams() -> list[dict]:
    """List all teams."""
    resp = await client().get(f"{API_BASE}/teams")
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def get_team(team_id: int) -> dict:
    """Get full details for a team by ID."""
    resp = await client().get(f"{API_BASE}/teams/{team_id}")
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def create_team(
    name: str,
    password: str,
    email: str = "",
    affiliation: str = "",
    country: str = "",
    hidden: bool = False,
    banned: bool = False,
) -> dict:
    """Create a new team."""
    payload: dict[str, Any] = {
        "name": name,
        "password": password,
        "hidden": hidden,
        "banned": banned,
    }
    if email:
        payload["email"] = email
    if affiliation:
        payload["affiliation"] = affiliation
    if country:
        payload["country"] = country
    resp = await client().post(f"{API_BASE}/teams", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_team(team_id: int) -> dict:
    """Delete a team by ID."""
    resp = await client().delete(f"{API_BASE}/teams/{team_id}")
    return _raise_for_status(resp)


# ===========================================================================
# SCOREBOARD & SUBMISSIONS
# ===========================================================================


@mcp.tool()
async def get_scoreboard() -> list[dict]:
    """Return the current scoreboard standings."""
    resp = await client().get(f"{API_BASE}/scoreboard")
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def list_submissions(
    challenge_id: int = 0,
    user_id: int = 0,
    type: str = "",
) -> list[dict]:
    """List flag submission attempts. Optionally filter by challenge_id, user_id, or type (correct/incorrect/already-solved)."""
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    if user_id:
        params["user_id"] = user_id
    if type:
        params["type"] = type
    resp = await client().get(f"{API_BASE}/submissions", params=params)
    return _raise_for_status(resp).get("data", [])


# ===========================================================================
# SOLUTIONS (write-ups / official walkthroughs)
# ===========================================================================


@mcp.tool()
async def list_solutions(
    challenge_id: int = 0,
    state: Literal["hidden", "visible", "solved", ""] = "",
) -> list[dict]:
    """List solutions (write-ups). Optionally filter by challenge_id or state.

    Args:
        challenge_id: Only return solutions for this challenge.
        state: Filter by state — "hidden", "visible", or "solved".
    """
    params: dict[str, Any] = {}
    if challenge_id:
        params["challenge_id"] = challenge_id
    if state:
        params["state"] = state
    resp = await client().get(f"{API_BASE}/solutions", params=params)
    return _raise_for_status(resp).get("data", [])


@mcp.tool()
async def get_solution(solution_id: int) -> dict:
    """Get a single solution by ID."""
    resp = await client().get(f"{API_BASE}/solutions/{solution_id}")
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def create_solution(
    challenge_id: int,
    content: str,
    state: Literal["hidden", "visible", "solved"] = "hidden",
) -> dict:
    """Create a solution (write-up / official walkthrough) for a challenge.

    Args:
        challenge_id: Challenge this solution belongs to.
        content: The solution text (Markdown or plain text walkthrough).
        state: "hidden" (default — not shown to anyone), "visible" (public),
               or "solved" (shown only to players who have solved the challenge).
    """
    payload = {
        "challenge_id": challenge_id,
        "content": content,
        "state": state,
    }
    resp = await client().post(f"{API_BASE}/solutions", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def update_solution(
    solution_id: int,
    content: str = "",
    state: Literal["hidden", "visible", "solved", ""] = "",
) -> dict:
    """Update a solution's content or state.

    Args:
        solution_id: ID of the solution to update.
        content: Replacement content (omit to leave unchanged).
        state: "hidden", "visible", "solved", or omit to leave unchanged.
    """
    payload: dict[str, Any] = {}
    if content:
        payload["content"] = content
    if state:
        payload["state"] = state
    if not payload:
        raise ValueError("No fields provided to update")
    resp = await client().patch(f"{API_BASE}/solutions/{solution_id}", json=payload)
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def delete_solution(solution_id: int) -> dict:
    """Delete a solution by ID."""
    resp = await client().delete(f"{API_BASE}/solutions/{solution_id}")
    return _raise_for_status(resp)


# ===========================================================================
# CONFIGURATION
# ===========================================================================


@mcp.tool()
async def get_configs() -> dict:
    """Return the full CTFd instance configuration (name, description, start/end times, etc.)."""
    resp = await client().get(f"{API_BASE}/configs")
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def update_configs(updates: dict) -> dict:
    """Update one or more CTFd configuration keys.

    Pass a flat dict of key→value pairs, e.g.:
      {"ctf_name": "My CTF", "start": "2024-01-01T00:00:00Z", "end": "2024-01-02T00:00:00Z"}

    Common keys: ctf_name, ctf_description, start, end, freeze,
                 user_mode (teams/users), registration_visibility,
                 challenge_visibility, account_visibility, score_visibility.
    """
    resp = await client().patch(f"{API_BASE}/configs", json=updates)
    return _raise_for_status(resp).get("data", {})


# ===========================================================================
# BULK / CONVENIENCE
# ===========================================================================


@mcp.tool()
async def create_full_challenge(
    name: str,
    category: str,
    description: str,
    value: int,
    flags: list[str],
    hints: list[str] = [],
    hint_costs: list[int] = [],
    tags: list[str] = [],
    type: str = "standard",
    state: str = "hidden",
    connection_info: str = "",
) -> dict:
    """Create a challenge together with its flags, hints, and tags in one call.

    This is the primary tool for an agent building a full competition — it
    avoids multiple round-trips by composing the lower-level tools internally.

    Args:
        name: Challenge title.
        category: Category (e.g. "Web", "Crypto", "Forensics").
        description: Problem statement shown to players.
        value: Point value (for standard challenges).
        flags: List of flag strings (e.g. ["CTF{flag1}", "CTF{alt_flag}"]).
        hints: List of hint strings (in order).
        hint_costs: Point costs per hint; defaults to 0 for each.
        tags: Tag strings (e.g. ["beginner", "sql"]).
        type: "standard" or "dynamic".
        state: "hidden" or "visible".
        connection_info: Optional service address shown to players.
    """
    # 1. Create challenge
    chall_payload: dict[str, Any] = {
        "name": name,
        "category": category,
        "description": description,
        "state": state,
        "type": type,
        "value": value,
    }
    if connection_info:
        chall_payload["connection_info"] = connection_info

    resp = await client().post(f"{API_BASE}/challenges", json=chall_payload)
    chall = _raise_for_status(resp)["data"]
    cid = chall["id"]

    # 2. Flags
    created_flags = []
    for flag in flags:
        r = await client().post(
            f"{API_BASE}/flags",
            json={"challenge_id": cid, "content": flag, "type": "static"},
        )
        created_flags.append(_raise_for_status(r)["data"])

    # 3. Hints
    created_hints = []
    for i, hint_text in enumerate(hints):
        cost = hint_costs[i] if i < len(hint_costs) else 0
        r = await client().post(
            f"{API_BASE}/hints",
            json={"challenge_id": cid, "content": hint_text, "cost": cost},
        )
        created_hints.append(_raise_for_status(r)["data"])

    # 4. Tags
    created_tags = []
    for tag in tags:
        r = await client().post(
            f"{API_BASE}/tags",
            json={"challenge_id": cid, "value": tag},
        )
        created_tags.append(_raise_for_status(r)["data"])

    return {
        "challenge": chall,
        "flags": created_flags,
        "hints": created_hints,
        "tags": created_tags,
    }


@mcp.tool()
async def publish_challenge(challenge_id: int) -> dict:
    """Make a previously hidden challenge visible to players."""
    resp = await client().patch(
        f"{API_BASE}/challenges/{challenge_id}",
        json={"state": "visible"},
    )
    return _raise_for_status(resp).get("data", {})


@mcp.tool()
async def publish_all_challenges() -> list[dict]:
    """Set all hidden challenges to visible in one operation."""
    list_resp = await client().get(f"{API_BASE}/challenges", params={"state": "hidden"})
    challenges = _raise_for_status(list_resp).get("data", [])
    results = []
    for chall in challenges:
        resp = await client().patch(
            f"{API_BASE}/challenges/{chall['id']}",
            json={"state": "visible"},
        )
        results.append(_raise_for_status(resp).get("data", {}))
    return results


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
