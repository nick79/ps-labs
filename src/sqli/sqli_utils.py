from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal
from urllib.parse import urljoin

import requests

from src.common.http_utils import HttpClient


@dataclass(slots=True)
class SqliResult:
    success: bool
    url: str
    status_code: int
    elapsed_s: float
    body: str
    evidence_excerpt: str = ""


def sqli_inject(
    client: HttpClient,
    payload: str,
    *,
    method: Literal["GET", "POST"] = "GET",
    endpoint: str = "/filter",
    inject: Literal["query", "body", "header", "cookie"] = "query",
    param_name: str = "category",
    base_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    success_marker: str | None = None,
    success_regex: str | None = None,
    expect_status: int | None = None,
) -> SqliResult:
    """
    Generic SQLi request + detection helper.
    - inject="query"  -> payload goes in URL params (?param_name=<payload>)
    - inject="body"   -> payload goes in form body (param_name=<payload>)
    - inject="header" -> payload goes in header: {param_name: <payload>}
    - inject="cookei" -> payload goes in cookie: {param_name: <payload>}

    Detectors can be combined: status code, substring marker, or regex.
    """
    session: requests.Session = client.session
    url: str = urljoin(client.base_url + "/", endpoint.lstrip("/"))

    params: dict[str, str] | None = None
    data: dict[str, str] | None = None
    hdrs: dict[str, str] | None = dict(extra_headers or {})
    cks: dict[str, str] = dict(cookies or {})

    if inject == "query":
        params = dict(base_params or {})
        params[param_name] = payload
    elif inject == "body":
        data = dict(base_params or {})
        data[param_name] = payload
    elif inject == "header":
        hdrs[param_name] = payload
    elif inject == "cookie":
        cks[param_name] = payload
    else:
        raise ValueError(f"Unsupported inject mode: {inject}")

    if method not in {"GET", "POST"}:
        raise ValueError(f"Unsupported method: {method}")

    resp = session.request(
        method=method,
        url=url,
        params=params,
        data=data,
        headers=hdrs,
        cookies=cks,
        timeout=client.timeout,
        verify=client.verify_tls,
    )

    text = resp.text or ""
    ok = True

    if expect_status is not None:
        ok = ok and (resp.status_code == expect_status)

    if success_marker is not None:
        ok = ok and (success_marker in text)

    if success_regex is not None:
        ok = ok and (re.search(success_regex, text) is not None)

    excerpt = text[:200]
    return SqliResult(
        success=ok,
        url=resp.url,
        status_code=resp.status_code,
        elapsed_s=resp.elapsed.total_seconds(),
        body=text,
        evidence_excerpt=excerpt,
    )
