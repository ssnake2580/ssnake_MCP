#!/usr/bin/env python3
import argparse
import asyncio
import json
import sys
from typing import Any, Dict, List

from mcp import ClientSession
from mcp.client.sse import sse_client
from openai import OpenAI
from rich import print


DEFAULT_BURP_SSE_URL = "http://127.0.0.1:19876/sse"
DEFAULT_LMSTUDIO_URL = "http://127.0.0.1:1234/v1"
DEFAULT_API_KEY = "lm-studio"

SYSTEM = """You are a vulnerability analyst sitting directly on Burp Suite.
Rules:
- Only use real data you obtain via MCP tools. Never assume.
- Keep confirmation steps non-destructive.
- If you need data, call tools instead of guessing.
"""


def mcp_tools_to_openai_tools(mcp_tools: List[Any]) -> List[Dict[str, Any]]:
    """Convert MCP tool definitions into OpenAI tool schema."""
    tools: List[Dict[str, Any]] = []
    for t in mcp_tools:
        schema = getattr(t, "inputSchema", None) or {"type": "object", "properties": {}}
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": getattr(t, "description", "") or "",
                    "parameters": schema,
                },
            }
        )
    return tools


async def run_agent(model: str, burp_sse_url: str, lmstudio_url: str, api_key: str) -> None:
    print(f"[cyan]Connecting to Burp MCP (SSE):[/cyan] {burp_sse_url}")
    try:
        async with sse_client(url=burp_sse_url) as streams, ClientSession(*streams) as session:
            try:
                await session.initialize()
            except Exception as exc:
                print(f"[red]MCP initialization failed:[/red] {exc}")
                print("[yellow]Check Caddy on 127.0.0.1:19876 and Burp MCP on 127.0.0.1:9876.[/yellow]")
                return

            try:
                tools_resp = await session.list_tools()
            except Exception as exc:
                print(f"[red]MCP tool listing failed:[/red] {exc}")
                print("[yellow]If you see 403/Origin errors, ensure Caddy is running.[/yellow]")
                return

            tool_names = [t.name for t in tools_resp.tools]
            print(f"[green]Connected.[/green] Tools available: {tool_names}")

            client = OpenAI(base_url=lmstudio_url, api_key=api_key)
            try:
                client.models.list()
            except Exception as exc:
                print(f"[red]LM Studio API not reachable:[/red] {exc}")
                print("[yellow]Start the Local Server and verify http://127.0.0.1:1234/v1/models.[/yellow]")
                return

            openai_tools = mcp_tools_to_openai_tools(tools_resp.tools)

            messages = [{"role": "system", "content": SYSTEM}]
            print("[green]Ready.[/green] Type a question (Ctrl+C to exit).")

            while True:
                user = input("> ").strip()
                if not user:
                    continue

                messages.append({"role": "user", "content": user})
                try:
                    resp = client.chat.completions.create(
                        model=model,
                        messages=messages,
                        tools=openai_tools,
                    )
                except Exception as exc:
                    print(f"[red]LM Studio request failed:[/red] {exc}")
                    continue

                msg = resp.choices[0].message
                content = msg.content or ""
                tool_calls = msg.tool_calls or []

                if not tool_calls:
                    print(content)
                    messages.append({"role": "assistant", "content": content})
                    continue

                messages.append(
                    {
                        "role": "assistant",
                        "content": content,
                        "tool_calls": [tc.model_dump() for tc in tool_calls],
                    }
                )

                for call in tool_calls:
                    name = call.function.name
                    args_raw = call.function.arguments or "{}"
                    try:
                        args = json.loads(args_raw)
                    except Exception:
                        args = {"raw": args_raw}

                    print(f"[dim]-> calling MCP tool: {name}({args})[/dim]")
                    try:
                        result = await session.call_tool(name, arguments=args)
                        tool_result_payload = {
                            "tool": name,
                            "result": [getattr(c, "text", str(c)) for c in result.content],
                            "structured": getattr(result, "structuredContent", None),
                        }
                        content_str = json.dumps(tool_result_payload)
                    except Exception as exc:
                        print(f"[red]Tool execution failed:[/red] {exc}")
                        content_str = json.dumps({"error": str(exc), "status": "failed"})

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "name": name,
                            "content": content_str,
                        }
                    )

                resp2 = client.chat.completions.create(model=model, messages=messages)
                msg2 = resp2.choices[0].message
                content2 = msg2.content or ""
                print(content2)
                messages.append({"role": "assistant", "content": content2})
    except Exception as exc:
        print(f"[red]Connection failed:[/red] {exc}")
        print("[yellow]Ensure Caddy is running and the Burp MCP extension is enabled.[/yellow]")
        return


def main() -> None:
    p = argparse.ArgumentParser(description="LM Studio + Burp MCP (SSE) agent")
    p.add_argument("model", help="LM Studio model id (see /v1/models)")
    p.add_argument("--burp", default=DEFAULT_BURP_SSE_URL, help=f"Burp MCP SSE URL (default: {DEFAULT_BURP_SSE_URL})")
    p.add_argument(
        "--lmstudio",
        default=DEFAULT_LMSTUDIO_URL,
        help=f"LM Studio OpenAI base URL (default: {DEFAULT_LMSTUDIO_URL})",
    )
    p.add_argument("--api-key", default=DEFAULT_API_KEY, help="API key for OpenAI-compatible server")
    args = p.parse_args()

    asyncio.run(run_agent(args.model, args.burp, args.lmstudio, args.api_key))


if __name__ == "__main__":
    main()
