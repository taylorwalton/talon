#!/usr/bin/env python3
"""
mysql_query.py — execute MySQL via pymysql, output JSON.

Invoked by /usr/local/bin/mysql-query AFTER the wrapper has sudo'd to
mcp-mysql and sourced /etc/mcp-secrets/mysql.env. Connection details
live in environment variables; this script never sees them on disk.

Reads SQL from stdin. Multi-statement scripts (separated by ';') run
sequentially in a single connection. Returns a JSON object for a single
statement, or a JSON array of objects for multi-statement input.

Usage (NOT called directly — use mysql-query):
    /opt/mysql-tools/bin/python /opt/mysql-tools/lib/mysql_query.py < script.sql
"""

import json
import os
import sys
from datetime import date, datetime, timedelta
from decimal import Decimal

import pymysql
import pymysql.cursors


def json_default(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return str(obj)
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    raise TypeError(f"unserialisable: {type(obj).__name__}")


def split_statements(sql):
    """Split on ';' but respect quoted strings and escaped chars."""
    statements = []
    current = []
    in_str = None
    escaped = False
    for ch in sql:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            current.append(ch)
            escaped = True
            continue
        if in_str:
            current.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            current.append(ch)
            continue
        if ch == ";":
            stmt = "".join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def main():
    sql = sys.stdin.read()
    if not sql.strip():
        print(json.dumps({"error": "empty SQL"}), file=sys.stderr)
        sys.exit(1)

    statements = split_statements(sql)
    if not statements:
        print(json.dumps({"error": "no executable statements"}), file=sys.stderr)
        sys.exit(1)

    conn = pymysql.connect(
        host=os.environ["MYSQL_HOST"],
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ["MYSQL_USER"],
        password=os.environ.get("MYSQL_PASS", os.environ.get("MYSQL_PASSWORD", "")),
        database=os.environ.get("MYSQL_DB", ""),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=10,
    )

    results = []
    try:
        with conn.cursor() as cur:
            for stmt in statements:
                cur.execute(stmt)
                try:
                    rows = cur.fetchall()
                    results.append({
                        "statement": stmt[:200],
                        "rowcount": cur.rowcount,
                        "rows": rows,
                    })
                except pymysql.err.ProgrammingError:
                    results.append({
                        "statement": stmt[:200],
                        "rowcount": cur.rowcount,
                        "rows": None,
                    })
    finally:
        conn.close()

    if len(results) == 1:
        print(json.dumps(results[0], default=json_default, indent=2))
    else:
        print(json.dumps(results, default=json_default, indent=2))


if __name__ == "__main__":
    try:
        main()
    except pymysql.err.MySQLError as e:
        print(json.dumps({"error": "MySQL error", "code": e.args[0] if e.args else None, "message": str(e)}), file=sys.stderr)
        sys.exit(2)
    except KeyError as e:
        print(json.dumps({"error": f"missing required env var: {e.args[0]}"}), file=sys.stderr)
        sys.exit(3)
