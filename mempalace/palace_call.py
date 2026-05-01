#!/usr/bin/env python3
"""One-shot MemPalace helper invoked by NanoClaw's node process.

Reads a JSON request on stdin, dispatches to the mempalace Python API,
and writes a JSON response on stdout. Used by src/palace-client.ts to
back the POST /palace/lesson and GET /palace/search HTTP endpoints.

Supported ops:
  {"op": "add_drawer", "wing": "...", "room": "...",
   "content": "...", "source_file": "...", "added_by": "..."}
  {"op": "search", "query": "...", "wing": "...", "room": "...", "limit": 5}
  {"op": "delete_drawer", "drawer_id": "..."}

The response is always a JSON object. On success it mirrors the mempalace
tool return; on failure it contains {"error": "..."}.

Errors are printed to stderr; stdout is reserved for the JSON response so
the node caller can parse it cleanly.
"""

import contextlib
import json
import sys
import traceback


def main() -> int:
    try:
        raw = sys.stdin.read()
        req = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid JSON on stdin: {e}"}))
        return 2

    op = req.get("op")
    if not op:
        print(json.dumps({"error": "missing 'op' field"}))
        return 2

    try:
        from mempalace import mcp_server as m
    except ImportError as e:
        print(json.dumps({"error": f"mempalace not installed: {e}"}))
        return 3

    # Redirect mempalace's stdout output (chromadb internals + mempalace's
    # own print() lines like "Filed drawer: ..." or "Fixed N BLOB seq_ids
    # in embeddings") to stderr for the duration of the tool call. Our
    # caller (src/palace-client.ts) parses stdout as JSON, so any non-JSON
    # noise on stdout breaks the round trip. Stderr is fine — node logs
    # it at debug.
    try:
        with contextlib.redirect_stdout(sys.stderr):
            if op == "add_drawer":
                result = m.tool_add_drawer(
                    wing=req["wing"],
                    room=req["room"],
                    content=req["content"],
                    source_file=req.get("source_file"),
                    added_by=req.get("added_by", "copilot-review"),
                )
            elif op == "search":
                result = m.tool_search(
                    query=req["query"],
                    limit=int(req.get("limit", 5)),
                    wing=req.get("wing"),
                    room=req.get("room"),
                )
            elif op == "delete_drawer":
                # Used by CoPilot's durability sweeper to forget expired
                # one-off lessons so they stop surfacing in palace searches.
                result = m.tool_delete_drawer(drawer_id=req["drawer_id"])
            else:
                result = {"error": f"unknown op: {op}"}
    except KeyError as e:
        result = {"error": f"missing required field: {e}"}
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        result = {"error": str(e)}

    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
