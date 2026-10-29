"""Typed, env-driven configuration for the Lumu MCP Server.

This is the single source of truth for configuration and the ONLY module that
reads the environment. Everything else receives a validated ``AppSettings``
instance (dependency injection) — no module-level singletons, no scattered
``os.getenv`` calls.

Background: MCP SDK v2 made ``mcp.settings`` a plain Pydantic model that no
longer reads ``MCP_*`` environment variables or ``.env`` files. The official
guidance is to read the environment yourself and pass values in. We do that
here with ``pydantic-settings`` and an application-specific ``LUMU_`` prefix so
nothing is mistaken for an SDK feature.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, PrivateAttr, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Transports the MCP SDK supports. stdio is the default and the only transport
#: the Claude Desktop integration uses; the others are available for advanced
#: HTTP deployments but are not part of the documented, supported surface.
Transport = Literal["stdio", "streamable-http", "sse"]

#: Default base URL for the Lumu Defender REST API.
DEFAULT_API_BASE_URL = "https://defender.lumu.io/api"


class TransportSettings(BaseSettings):
    """How the server is exposed to clients.

    v2 moved transport configuration off the ``MCPServer`` constructor and onto
    ``run()`` / the app factories, so the application owns these values. For the
    stdio deployment used by Claude Desktop, ``run_kwargs()`` returns ``{}``.
    """

    model_config = SettingsConfigDict(
        env_prefix="LUMU_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    transport: Transport = Field(
        default="stdio",
        description="MCP transport to serve. Default 'stdio' (Claude Desktop).",
    )
    host: str = Field(
        default="127.0.0.1",
        description="Bind host for HTTP transports. Loopback by default.",
    )
    port: int = Field(
        default=8000, ge=1, le=65535,
        description="Bind port for HTTP transports.",
    )
    streamable_http_path: str = Field(
        default="/mcp",
        description="URL path for the streamable-http transport.",
    )
    json_response: bool = Field(
        default=False,
        description="Return JSON responses instead of SSE (streamable-http).",
    )
    stateless_http: bool = Field(
        default=False,
        description="Run streamable-http without persistent sessions.",
    )
    max_request_body_size: int = Field(
        default=4 * 1024 * 1024,
        description="Max HTTP POST body size in bytes (SDK default is 4 MiB).",
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts allowed by DNS-rebinding protection (HTTP only).",
    )
    allowed_origins: list[str] = Field(
        default_factory=list,
        description="Origins allowed by DNS-rebinding protection (HTTP only).",
    )

    def run_kwargs(self) -> dict:
        """Keyword arguments for ``MCPServer.run(transport, **kwargs)``.

        stdio accepts no transport kwargs, so it returns an empty dict. HTTP
        transports receive host/port/body-size and, when configured, the
        DNS-rebinding allowlist via ``TransportSecuritySettings``.
        """
        if self.transport == "stdio":
            return {}

        kwargs: dict = {
            "host": self.host,
            "port": self.port,
            "max_request_body_size": self.max_request_body_size,
        }
        if self.transport == "streamable-http":
            kwargs |= {
                "streamable_http_path": self.streamable_http_path,
                "json_response": self.json_response,
                "stateless_http": self.stateless_http,
            }
        if self.allowed_hosts or self.allowed_origins:
            # Imported lazily so stdio deployments never import HTTP machinery.
            from mcp.server.transport_security import TransportSecuritySettings

            kwargs["transport_security"] = TransportSecuritySettings(
                allowed_hosts=self.allowed_hosts,
                allowed_origins=self.allowed_origins,
            )
        return kwargs


class AppSettings(BaseSettings):
    """Top-level application configuration.

    All variables use the ``LUMU_`` prefix. The Lumu Defender API key keeps its
    historical name ``LUMU_DEFENDER_API_KEY`` (prefix ``LUMU_`` + field
    ``defender_api_key``), so existing Claude Desktop configs keep working.
    """

    model_config = SettingsConfigDict(
        env_prefix="LUMU_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Server identity -------------------------------------------------
    name: str = Field(
        default="lumu-mcp-server",
        description="MCP server name reported to clients.",
    )
    instructions: str | None = Field(
        default=(
            "Query and manage Lumu Defender security incidents: list, inspect, "
            "comment on, mute/unmute, mark as read, and close incidents."
        ),
        description="Human/model-facing instructions reported to clients.",
    )

    # --- Observability ---------------------------------------------------
    debug: bool = Field(
        default=False,
        description="Enable SDK debug mode.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level for the server and SDK.",
    )

    # --- Lumu Defender API ----------------------------------------------
    # Required. Reads LUMU_DEFENDER_API_KEY. Missing -> fail fast at startup.
    defender_api_key: SecretStr = Field(
        description="Lumu Defender API key (env: LUMU_DEFENDER_API_KEY).",
    )
    api_base_url: str = Field(
        default=DEFAULT_API_BASE_URL,
        description="Base URL of the Lumu Defender REST API.",
    )
    request_timeout: float = Field(
        default=30.0, gt=0,
        description="HTTP request timeout in seconds for Lumu API calls.",
    )

    # Transport config is its own env-driven model (LUMU_TRANSPORT, LUMU_HOST, …).
    # It is exposed as a memoized property rather than a nested field so the two
    # settings models don't collide on the LUMU_TRANSPORT variable.
    _transport: TransportSettings | None = PrivateAttr(default=None)

    @property
    def transport(self) -> TransportSettings:
        """Transport configuration (lazily constructed from the environment)."""
        if self._transport is None:
            self._transport = TransportSettings()
        return self._transport

    @property
    def version(self) -> str:
        """Server version, sourced from the installed package metadata."""
        from lumu_mcp_server import __version__

        return __version__
