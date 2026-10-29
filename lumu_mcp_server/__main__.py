"""Entry point for the Lumu MCP Server.

Loads settings from the environment (fail-fast if a required variable is
missing), builds the server, and runs it over the configured transport.
"""

from __future__ import annotations

import logging
import sys

from pydantic import ValidationError

from .config import AppSettings
from .server import build_server


def _configure_logging(level: str) -> None:
    """Configure root logging to stderr (never stdout — stdout is the stdio transport)."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    """Load configuration, build the server, and run it."""
    try:
        settings = AppSettings()
    except ValidationError as exc:
        # Fail fast with a clear, non-tracebacky message naming the variable(s).
        missing = ", ".join(
            "LUMU_" + ".".join(str(p) for p in err["loc"]).upper()
            for err in exc.errors()
        )
        print(
            f"❌ Configuration error: missing/invalid setting(s): {missing}\n"
            "   Set LUMU_DEFENDER_API_KEY (and see .env.example for all options).",
            file=sys.stderr,
        )
        sys.exit(1)

    _configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)
    logger.info("Starting %s v%s", settings.name, settings.version)

    server = build_server(settings)
    transport = settings.transport

    try:
        server.run(transport=transport.transport, **transport.run_kwargs())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as exc:
        logger.error("Server error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
