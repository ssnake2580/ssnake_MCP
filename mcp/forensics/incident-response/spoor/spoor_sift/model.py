"""LLM model factory — provider-agnostic, env-driven.

Default path is OpenRouter (OpenAI-compatible); direct Anthropic is a drop-in
fallback. The provider is chosen from the environment, so it's config, not code.

Call ``load_env()`` once at an entry point to also pick up a repo-local ``.env``
(``os.environ`` always wins, so a shell / ``~/Documents/secret/.env`` key takes
precedence over a committed-by-mistake ``.env``). Secrets never live in the repo.
"""

from __future__ import annotations

import os

DEFAULT_MODEL = "anthropic/claude-sonnet-4.6"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# Providers reserve max_tokens against credit limits per request; uncapped models
# reserve their maximum (~65K) and can starve a key mid-run. 16K comfortably fits
# the largest artifact in the system (the full incident report).
DEFAULT_MAX_TOKENS = 16384


def load_env() -> None:
    """Load a repo-local .env as a fallback (does not override existing env vars)."""
    from dotenv import load_dotenv

    load_dotenv()


def _model_id(role: str) -> str:
    if role == "lead":
        return (
            os.environ.get("SPOOR_LEAD_MODEL")
            or os.environ.get("SPOOR_MODEL")
            or DEFAULT_MODEL
        )
    return os.environ.get("SPOOR_MODEL") or DEFAULT_MODEL


def _openrouter_key() -> str | None:
    # Per-project key (RECTOR's convention) first, then the generic name (judges).
    return os.environ.get("SPOOR_OPENROUTER_API_KEY") or os.environ.get("OPENROUTER_API_KEY")


def _anthropic_key() -> str | None:
    return os.environ.get("SPOOR_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")


def build_chat_model(role: str = "specialist", *, temperature: float = 0.0):
    """Build a LangChain chat model for ``role`` ('specialist' | 'lead') from env.

    Order of preference: OpenRouter (``SPOOR_OPENROUTER_API_KEY`` → ``OPENROUTER_API_KEY``)
    → Anthropic (``SPOOR_ANTHROPIC_API_KEY`` → ``ANTHROPIC_API_KEY``). Raises if none set.
    """
    model_id = _model_id(role)
    max_tokens = int(os.environ.get("SPOOR_MAX_TOKENS", DEFAULT_MAX_TOKENS))

    openrouter_key = _openrouter_key()
    if openrouter_key:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model_id,
            api_key=openrouter_key,
            base_url=os.environ.get("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL),
            temperature=temperature,
            max_tokens=max_tokens,
        )

    anthropic_key = _anthropic_key()
    if anthropic_key:
        from langchain_anthropic import ChatAnthropic

        native = model_id.split("/", 1)[-1]  # strip "anthropic/" for the native SDK
        return ChatAnthropic(
            model=native, api_key=anthropic_key, temperature=temperature,
            max_tokens=max_tokens,
        )

    raise RuntimeError(
        "No LLM key found. Set SPOOR_OPENROUTER_API_KEY / OPENROUTER_API_KEY (preferred) "
        "or SPOOR_ANTHROPIC_API_KEY / ANTHROPIC_API_KEY in your shell, "
        "~/Documents/secret/.env, or ./.env"
    )
