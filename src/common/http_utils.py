from dataclasses import dataclass
import os

import requests
from requests.adapters import HTTPAdapter
import urllib3
from urllib3.util.retry import Retry


@dataclass(slots=True)
class HttpConfig:
    base_url: str
    verify_tls: bool
    timeout: float = 10.0  # seconds
    proxies: dict[str, str] | None = None
    user_agent: str = "labs-client/1.0 (+https://portswigger.net/web-security)"


@dataclass(slots=True)
class HttpClient:
    """A thin, type-safe wrapper around a configured requests.Session."""

    session: requests.Session
    base_url: str
    timeout: float
    verify_tls: bool


def _clean_env_proxies() -> dict[str, str]:
    # Gather from env, drop Nones/empties, and ensure str->str
    raw: dict[str, str | None] = {
        "http": os.getenv("HTTP_PROXY") or os.getenv("http_proxy"),
        "https": os.getenv("HTTPS_PROXY") or os.getenv("https_proxy"),
    }
    return {k: v for k, v in raw.items() if isinstance(v, str) and v}


def build_client(cfg: HttpConfig) -> HttpClient:
    """
    Create a configured HTTP client with:
    - requests.Session
    - Retries on common transient/idempotent errors
    - Optional proxy support (e.g. Burp at 127.0.0.1:8080)
    - Custom User-Agent
    """
    if not cfg.verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session: requests.Session = requests.Session()

    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Proxies from cfg or environment; strip empty values
    proxies: dict[str, str] | None = cfg.proxies if cfg.proxies else _clean_env_proxies() or None
    if proxies:
        session.proxies.update(proxies)

    session.headers.update({"User-Agent": cfg.user_agent})

    return HttpClient(
        session=session,
        base_url=cfg.base_url.rstrip("/"),
        timeout=cfg.timeout,
        verify_tls=cfg.verify_tls,
    )
