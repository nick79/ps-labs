"""Shared CLI helpers for SQLi lab scripts."""
from __future__ import annotations

from collections.abc import Iterable

from src.common.http_utils import HttpClient, HttpConfig, build_client


def parse_keyvals(items: Iterable[str] | None, sep: str) -> dict[str, str]:
    """Convert sequences like ["key=value"] into a dictionary."""
    out: dict[str, str] = {}
    if not items:
        return out

    for item in items:
        if sep not in item:
            raise ValueError(f"Invalid format '{item}', expected KEY{sep}VALUE")
        key, value = item.split(sep, 1)
        out[key.strip()] = value.strip()

    return out


def build_cli_client(
    base_url: str,
    *,
    proxy: str | None,
    insecure: bool,
    timeout: float,
) -> HttpClient:
    """Instantiate a configured HttpClient using common CLI flags."""
    proxies: dict[str, str] | None = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    cfg = HttpConfig(
        base_url=base_url.strip(),
        verify_tls=not insecure,
        timeout=timeout,
        proxies=proxies,
    )
    return build_client(cfg)
