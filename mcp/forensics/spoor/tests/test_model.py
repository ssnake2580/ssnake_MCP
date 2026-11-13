import pytest

from spoor_sift.model import build_chat_model


@pytest.fixture(autouse=True)
def _clear_provider_env(monkeypatch):
    # Fully hermetic: clear any provider keys/models from the real environment.
    for key in (
        "OPENROUTER_API_KEY",
        "SPOOR_OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "SPOOR_ANTHROPIC_API_KEY",
        "SPOOR_MODEL",
        "SPOOR_LEAD_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)


def _model_of(m):
    return getattr(m, "model", None) or getattr(m, "model_name", None)


def test_uses_openrouter_when_generic_key_present(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MODEL", "anthropic/claude-sonnet-4")

    from langchain_openai import ChatOpenAI

    model = build_chat_model("specialist")
    assert isinstance(model, ChatOpenAI)
    assert _model_of(model) == "anthropic/claude-sonnet-4"
    assert "openrouter.ai" in str(model.openai_api_base)


def test_uses_spoor_prefixed_openrouter_key(monkeypatch):
    # RECTOR's per-project convention: export SPOOR_OPENROUTER_API_KEY=...
    monkeypatch.setenv("SPOOR_OPENROUTER_API_KEY", "sk-or-spoor")
    monkeypatch.setenv("SPOOR_MODEL", "anthropic/claude-sonnet-4")

    from langchain_openai import ChatOpenAI

    assert isinstance(build_chat_model("specialist"), ChatOpenAI)


def test_lead_role_prefers_lead_model(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MODEL", "model-specialist")
    monkeypatch.setenv("SPOOR_LEAD_MODEL", "model-lead")
    assert _model_of(build_chat_model("lead")) == "model-lead"


def test_lead_falls_back_to_spoor_model(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MODEL", "model-specialist")
    assert _model_of(build_chat_model("lead")) == "model-specialist"


def test_falls_back_to_anthropic_when_only_anthropic_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("SPOOR_MODEL", "anthropic/claude-sonnet-4")

    from langchain_anthropic import ChatAnthropic

    model = build_chat_model("specialist")
    assert isinstance(model, ChatAnthropic)
    assert _model_of(model) == "claude-sonnet-4"


def test_raises_when_no_key():
    with pytest.raises(RuntimeError):
        build_chat_model()


def test_caps_max_tokens_by_default(monkeypatch):
    # Providers reserve max_tokens against credit limits per request; an uncapped
    # model reserves the model maximum (~65K) and can starve a key mid-run.
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    model = build_chat_model("specialist")
    assert model.max_tokens == 16384


def test_max_tokens_env_override(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("SPOOR_MAX_TOKENS", "8192")
    assert build_chat_model("specialist").max_tokens == 8192


def test_anthropic_path_also_caps_max_tokens(monkeypatch):
    # ChatAnthropic's own default is 1024 — far too small for an incident report.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("SPOOR_MODEL", "anthropic/claude-sonnet-4")
    assert build_chat_model("specialist").max_tokens == 16384
