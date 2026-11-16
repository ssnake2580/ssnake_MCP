"""FastMCP server — scapy-mcp entry point.

The ``Runtime`` class wraps a ``ScapySettings`` instance and lazily
constructs the FastMCP app on first access. The ``/readyz`` route returns
503 when any required feed reports unhealthy; capture/transmit are
optional, so their absence does NOT trigger 503.

Transmit tools are gated to the ``full`` profile (spec §6.3) — the
``standard`` and ``minimal`` profiles drop the transmit group via
``apply_tool_profile``.

Auth wiring (Task 14)
---------------------
``Runtime._build_auth_middleware()`` constructs a ``BearerTokenMiddleware``
when ``settings.auth.enabled`` is true and registers it via
``app.add_middleware(...)``. ``_build_auth_health_provider()`` returns the
``auth_health_provider`` callable for ``register_http_health_route`` so
``/health`` exposes the wiring-discipline §3 four signals
(``verifications_total``, ``errors_total``, ``last_updated_timestamp``,
``cycles_total``) under the ``auth`` component.
"""

from __future__ import annotations

import asyncio
import contextlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import Response
from fastmcp import FastMCP
from fastmcp.server.http import StarletteWithLifespan
from mcp_common.auth.core import JWTIdentityProvider
from mcp_common.auth.error_middleware import AuthErrorTranslationMiddleware
from mcp_common.auth.health import AuthHealth
from mcp_common.auth.identity import validate_auth_config
from mcp_common.auth.middleware import BearerTokenMiddleware
from mcp_common.auth.provider import IdentityProvider, ProviderHealth
from mcp_common.baseline_tools import register_baseline_tools, seed_liveness_context
from mcp_common.health import register_http_health_route
from mcp_common.tools.dispatch import ToolProfile, _apply_tool_profile_async

from scapy_mcp import __version__
from scapy_mcp.config.settings import ScapySettings, get_settings
from scapy_mcp.feeds import as_components, required_feeds_healthy
from scapy_mcp.tools.profiles import (
    PROFILE_REGISTRATIONS,
    SCAPY_MANDATORY_GROUPS,
    ServerBundle,
    register_all_tool_groups,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp_common.auth.config import AuthConfig

APP_NAME = "scapy-mcp"


def _run_async_safely(coro: Any) -> Any:
    """Bridge from sync (CLI / tests) into the async tool surface."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


def build_runtime(*, settings: ScapySettings | None = None) -> Runtime:
    s = settings or get_settings()
    return Runtime(settings=s)


class Runtime:
    def __init__(self, *, settings: ScapySettings) -> None:
        self.settings = settings
        self.asgi_app: StarletteWithLifespan | None = None
        self._mcp_app: FastMCP | None = None
        # Task 14: auth wiring state. Both are populated lazily by
        # _build_auth_middleware() during build_mcp_app_async().
        self._auth_middleware: BearerTokenMiddleware | None = None
        self._auth_providers: dict[str, IdentityProvider] = {}
        self._last_successful_verification_at: datetime | None = None

    def build_mcp_app(self) -> FastMCP:
        return asyncio.run(self.build_mcp_app_async())

    async def build_mcp_app_async(self) -> FastMCP:
        if self._mcp_app is not None:
            return self._mcp_app
        bundle = ServerBundle(settings=self.settings)
        app = FastMCP(name=APP_NAME, version=__version__)

        # Auth wiring (Task 14). Construct the middleware BEFORE the health
        # route so _build_auth_health_provider() can close over the live
        # middleware instance, then add it to FastMCP's middleware stack.
        # The middleware is a no-op when auth is disabled.
        auth_middleware = self._build_auth_middleware()
        if auth_middleware is not None:
            app.add_middleware(auth_middleware)
        # B2 fix: AuthError subclasses raised by BearerTokenMiddleware must be
        # translated to JSON-RPC -32001 with OAuth-style data. Install the
        # translator unconditionally so AuthErrors surfaced by future
        # middleware (or by @require_auth) hit the same shape end-to-end.
        app.add_middleware(AuthErrorTranslationMiddleware())

        # Baseline tools + liveness seed must precede domain registration so
        # the four ``EXPECTED_BASELINE`` names exist even if domain setup
        # raises later. Mirrors mcp-common's wiring discipline.
        seed_liveness_context(service_name=APP_NAME, version=__version__)
        register_baseline_tools(app)
        register_http_health_route(
            app,
            service_name=APP_NAME,
            version=__version__,
            extra_components=as_components(),
            auth_health_provider=self._build_auth_health_provider(),
        )

        registration_map = register_all_tool_groups(app, bundle)
        # The dispatch will RE-register per-profile groups below, so undo the
        # unconditional attachment we just did — otherwise ``standard`` would
        # keep ``transmit_packet`` because the dispatch only ADDS groups, it
        # does not remove tools that fall outside the active profile.
        for tool_name in (
            "craft_packet",
            "dissect_bytes",
            "read_pcap",
            "write_pcap",
            "capture_start",
            "capture_stop",
            "capture_read",
            "transmit_packet",
            "probe_packet",
            "health",
        ):
            local = getattr(app, "_local_provider", None)
            if local is not None and hasattr(local, "remove_tool"):
                with contextlib.suppress(KeyError, ValueError):
                    local.remove_tool(tool_name)

        profile_name = self.settings.tool_profile

        # ``register_all_fn`` is the FULL + ALL_TOOLS re-registration callable.
        # The contract is ``Callable[[FastMCP], None]`` — mcp-common's dispatch
        # discards the return value. Use a named helper rather than a lambda
        # so the side-effect intent (and the explicit ``-> None``) is visible
        # to the type checker; a lambda that returned the mapping dict would
        # mismatch ``Awaitable[None] | None``.
        def _register_all(srv: FastMCP) -> None:
            register_all_tool_groups(srv, bundle)

        await _apply_tool_profile_async(
            app,
            profile=ToolProfile(profile_name),
            profile_env_var="SCAPY_MCP_TOOL_PROFILE",
            registrations=PROFILE_REGISTRATIONS,
            registration_map=registration_map,
            register_all_fn=_register_all,
            mandatory_groups=SCAPY_MANDATORY_GROUPS,
            essential_tool_names={
                "discover_tools",
                "get_liveness",
                "get_readiness",
                "health_check_all",
            },
            discovery_fn=None,
        )

        self._mcp_app = app
        return app

    def build_asgi_app(self) -> StarletteWithLifespan:
        if self.asgi_app is not None:
            return self.asgi_app
        asgi = self.build_mcp_app().http_app()

        async def _readyz(_request: object) -> Response:
            if not required_feeds_healthy():
                return Response(
                    content='{"status":"degraded","reason":"required feed not healthy"}',
                    status_code=503,
                    media_type="application/json",
                )
            return Response(
                content='{"status":"ok"}',
                status_code=200,
                media_type="application/json",
            )

        asgi.add_route("/readyz", _readyz, methods=["GET"])  # type: ignore[arg-type]

        self.asgi_app = asgi
        return asgi

    def _build_auth_middleware(self) -> BearerTokenMiddleware | None:
        """Construct ``BearerTokenMiddleware`` when auth is enabled.

        Returns ``None`` when ``settings.auth`` is missing or
        ``auth.enabled`` is False — the FastMCP app then operates without
        auth, mirroring the pre-Task-14 behavior.

        For the JWT provider, the parent :class:`AuthConfig.secret`
        property raises :class:`SecretNotConfiguredError` when
        ``resolved_secret`` is None (i.e. neither an explicit value nor an
        env var was provided). We guard against that BEFORE the JWT
        provider construction so a sibling that mis-configures the
        ``identity_providers`` map (jwt listed but no secret) surfaces a
        clear ``RuntimeError`` to the operator instead of an
        ``AttributeError`` from ``SecretStr.get_secret_value()`` or a
        bare ``SecretNotConfiguredError`` from the property accessor.

        See mcp-common-auth-primitives plan §14 for the cross-repo wiring
        contract (this method is the canonical shape).
        """
        auth_cfg: AuthConfig | None = getattr(self.settings, "auth", None)
        if auth_cfg is None or not auth_cfg.enabled:
            return None

        # B6 fix: fail-loud at startup if the auth config is inconsistent
        # (empty trusted_issuers, missing default_provider, etc.) rather than
        # at the first request. Mirrors mcp-common's startup-check contract.
        validate_auth_config(auth_cfg)

        providers: dict[str, IdentityProvider] = {}
        identity_providers = auth_cfg.identity_providers or {}
        if "jwt" in identity_providers:
            # I-9 fix: guard the underlying field directly. ``auth_cfg.secret``
            # is a @property that raises SecretNotConfiguredError when
            # resolved_secret is None, so checking ``is None`` on the property
            # is unreachable. Use the public ``resolved_secret`` attribute
            # which carries the raw value (or None).
            if auth_cfg.resolved_secret is None:
                raise RuntimeError(
                    "auth.identity_providers['jwt'] is configured but "
                    "auth.secret is None — set SCAPY_MCP_AUTH__SECRET (or "
                    "BODAI_SHARED_SECRET), or remove the JWT provider."
                )
            providers["jwt"] = JWTIdentityProvider(
                name="jwt",
                secret=auth_cfg.resolved_secret,
                trusted_issuers=auth_cfg.trusted_issuers,
            )

        self._auth_providers = providers
        self._auth_middleware = BearerTokenMiddleware(
            auth_config=auth_cfg,
            providers=providers,
        )
        return self._auth_middleware

    def _build_auth_health_provider(self) -> Callable[[], AuthHealth | None] | None:
        """Return a sync callable that builds ``AuthHealth`` per ``/health`` request.

        ``register_http_health_route`` accepts
        ``Callable[[], AuthHealth | None]`` (NOT awaitable) and invokes it
        on every probe so transient flips in provider state surface in the
        next probe. The brief's draft used ``await AuthHealth.from_providers(...)``
        but ``from_providers`` is async; building the dataclass directly
        keeps the sync signature intact while still reading the live
        middleware counters (I-4 fix: no separate ``_auth_counters`` dict).

        Provider-level healths are constructed synchronously via
        ``ProviderHealth(name=..., state='healthy')`` — the providers in
        this codebase (JWT) have no remote dependency to poll, so a static
        ``healthy`` snapshot is correct. A future OAuth/JWKS provider
        should expose a sync ``cached_health`` accessor and the
        construction below should consult it.
        """
        if self._auth_middleware is None:
            return None

        def _provider() -> AuthHealth | None:
            mw = self._auth_middleware
            if mw is None:
                return None
            provider_healths: dict[str, ProviderHealth] = {
                name: ProviderHealth(name=name, state="healthy") for name in self._auth_providers
            }
            return AuthHealth(
                providers=provider_healths,
                verifications_total=mw.verifications_total,
                errors_total=mw.errors_total,
                last_successful_verification_at=self._last_successful_verification_at,
                last_updated_timestamp=datetime.now(UTC),
                cycles_total=1,
            )

        return _provider


_default_runtime: Runtime | None = None


def _get_runtime() -> Runtime:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = build_runtime()
    return _default_runtime


def get_app() -> FastMCP:
    """Lazy accessor — mirrors archive-org-mcp's pattern."""
    return _get_runtime().build_mcp_app()
