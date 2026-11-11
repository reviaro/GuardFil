"""GuardFil T2a OpenAI broker package."""

from typing import Any

__all__ = [
    "check_key",
    "load_key",
    "open_or_init_ledger",
    "run_smoke",
    "strict_json_loads",
    "write_evidence",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import smoke

        return getattr(smoke, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
