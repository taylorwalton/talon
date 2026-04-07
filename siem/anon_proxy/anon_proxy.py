#!/usr/bin/env python3
"""
Anonymizing MCP proxy for OpenSearch SIEM tools.

Wraps opensearch-mcp-server and intercepts tool results, replacing sensitive
field values with consistent session tokens before they reach the cloud model.

Token map is persisted at /workspace/group/session_tokens.json so tokens
remain consistent across all tool calls within a session.

Built-in tool: `deanonymize` — call this with a text block containing tokens
(USER_1, HOST_1, IP_INT_1, etc.) to get back the original values. Use it
when writing the final analyst report so names and IPs are accurate.

Usage:
  This script is invoked by anon-opensearch-mcp.sh (the MCP server command).
  It spawns opensearch-mcp.sh as a child and proxies all JSON-RPC messages,
  anonymizing tool results on the way through.
"""

import json
import os
import re
import sys
import ipaddress
import threading
import subprocess
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent
FIELDS_YAML = SCRIPT_DIR / "fields.yaml"
OPENSEARCH_WRAPPER = SCRIPT_DIR.parent / "opensearch-mcp.sh"
TOKEN_MAP_PATH = Path("/workspace/group/session_tokens.json")

# ── Token map ─────────────────────────────────────────────────────────────────

class TokenMap:
    """Persistent, session-scoped map of original PII values to opaque tokens."""

    def __init__(self):
        self._lock = threading.Lock()
        self.forward: dict[str, str] = {}   # original_value -> TOKEN_N
        self.counters: dict[str, int] = {}  # prefix -> last N assigned
        self._load()

    def _load(self):
        if TOKEN_MAP_PATH.exists():
            try:
                data = json.loads(TOKEN_MAP_PATH.read_text())
                self.forward = data.get("forward", {})
                self.counters = data.get("counters", {})
            except Exception:
                pass

    def _save(self):
        try:
            TOKEN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
            TOKEN_MAP_PATH.write_text(json.dumps(
                {"forward": self.forward, "counters": self.counters}, indent=2
            ))
        except Exception:
            pass  # Token map is best-effort; don't crash the proxy

    def get_or_create(self, value: str, prefix: str) -> str:
        """Return the token for *value* (creating one if needed)."""
        if not value or not value.strip():
            return value
        with self._lock:
            existing = self.forward.get(value)
            if existing:
                return existing
            n = self.counters.get(prefix, 0) + 1
            self.counters[prefix] = n
            token = f"{prefix}_{n}"
            self.forward[value] = token
            self._save()
            return token

    def reverse_all(self) -> dict[str, str]:
        """Return a token → original_value mapping for de-anonymization."""
        with self._lock:
            return {tok: orig for orig, tok in self.forward.items()}


# ── Field config ──────────────────────────────────────────────────────────────

def _load_fields() -> dict:
    if not FIELDS_YAML.exists():
        return {}
    if not HAS_YAML:
        sys.stderr.write(
            "[anon-proxy] WARNING: pyyaml not installed — field config unavailable, "
            "falling back to IP/path pattern scanning only.\n"
        )
        return {}
    try:
        with open(FIELDS_YAML) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        sys.stderr.write(f"[anon-proxy] WARNING: could not load fields.yaml: {e}\n")
        return {}


# ── Anonymizer ────────────────────────────────────────────────────────────────

# Regex: IPv4 addresses
_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Regex: Windows user path component   C:\Users\<name>\
_WIN_USER_PATH_RE = re.compile(r'(?i)(C:\\Users\\)([^\\]+)(\\)')

# Regex: Linux home directory path   /home/<name>/
_LINUX_HOME_RE = re.compile(r'(/home/)([^/]+)(/)')


def _is_internal_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


class Anonymizer:
    def __init__(self, token_map: TokenMap):
        self.token_map = token_map
        config = _load_fields()

        # field_name (and field_name.lower()) -> token_prefix
        self._field_index: dict[str, str] = {}
        # fields that must never be touched
        self._preserve: set[str] = set()

        for cat_name, cat in config.get("categories", {}).items():
            prefix = cat.get("token_prefix", cat_name.upper())
            for field in cat.get("fields", []):
                self._field_index[field] = prefix
                self._field_index[field.lower()] = prefix

        for field in config.get("preserve_fields", []):
            self._preserve.add(field)
            self._preserve.add(field.lower())

        self._internal_ip_prefix: str = config.get("internal_ip_token_prefix", "IP_INT")
        self._scan_user_paths: bool = config.get("scan_user_paths", True)
        self._scan_inline_ips: bool = config.get("scan_inline_ips", True)

    def _anonymize_string(self, field_name: str, value: str) -> str:
        """Anonymize a single string value for a given field."""
        if not value:
            return value

        fname_lower = field_name.lower()

        # Preserve fields: return unchanged
        if field_name in self._preserve or fname_lower in self._preserve:
            return value

        # Direct field mapping: replace entire value
        prefix = self._field_index.get(field_name) or self._field_index.get(fname_lower)
        if prefix:
            return self.token_map.get_or_create(value, prefix)

        # No direct mapping — apply pattern-based scanning
        return self._scan_patterns(value)

    def _scan_patterns(self, text: str) -> str:
        """Apply pattern-based anonymization to an arbitrary text string."""
        if self._scan_inline_ips:
            def _replace_ip(m: re.Match) -> str:
                ip = m.group(0)
                if _is_internal_ip(ip):
                    return self.token_map.get_or_create(ip, self._internal_ip_prefix)
                return ip
            text = _IP_RE.sub(_replace_ip, text)

        if self._scan_user_paths:
            # Windows: C:\Users\john.doe\  →  C:\Users\USER_1\
            def _replace_win(m: re.Match) -> str:
                username = m.group(2)
                token = self.token_map.get_or_create(username, "USER")
                return m.group(1) + token + m.group(3)
            text = _WIN_USER_PATH_RE.sub(_replace_win, text)

            # Linux: /home/john.doe/  →  /home/USER_1/
            def _replace_linux(m: re.Match) -> str:
                username = m.group(2)
                token = self.token_map.get_or_create(username, "USER")
                return m.group(1) + token + m.group(3)
            text = _LINUX_HOME_RE.sub(_replace_linux, text)

        return text

    def anonymize_obj(self, obj: Any, parent_key: str = "") -> Any:
        """Recursively walk a deserialized JSON object and anonymize PII values."""
        if isinstance(obj, dict):
            return {k: self._anonymize_value(k, v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.anonymize_obj(item, parent_key) for item in obj]
        elif isinstance(obj, str):
            return self._scan_patterns(obj)
        else:
            return obj

    def _anonymize_value(self, key: str, value: Any) -> Any:
        if isinstance(value, str):
            return self._anonymize_string(key, value)
        return self.anonymize_obj(value, key)

    def anonymize_content_blocks(self, content: list) -> list:
        """Anonymize MCP tool-result content blocks (list of {type, text})."""
        result = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "text":
                result.append(block)
                continue
            text = block.get("text", "")
            try:
                parsed = json.loads(text)
                anon = self.anonymize_obj(parsed)
                text = json.dumps(anon, ensure_ascii=False)
            except (json.JSONDecodeError, ValueError):
                text = self._scan_patterns(text)
            result.append({**block, "text": text})
        return result


# ── De-anonymize tool definition ──────────────────────────────────────────────

_DEANONYMIZE_TOOL = {
    "name": "deanonymize",
    "description": (
        "Reverse the anonymization applied to SIEM data during this session. "
        "Pass any text containing tokens like USER_1, HOST_2, IP_INT_3, EMAIL_1, etc., "
        "and receive the original values substituted back in. "
        "Always call this before writing the final analyst report so that usernames, "
        "hostnames, and internal IPs are accurate and meaningful to the analyst."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Text containing anonymization tokens to de-anonymize."
            }
        },
        "required": ["text"]
    }
}


# ── Proxy core ────────────────────────────────────────────────────────────────

class Proxy:
    """
    Bidirectional JSON-RPC proxy over stdin/stdout.

    Two threads run concurrently:
      • _client_to_child: reads from our stdin → forwards to child stdin
      • _child_to_client: reads from child stdout → anonymizes → writes to our stdout
    """

    def __init__(self):
        self.token_map = TokenMap()
        self.anonymizer = Anonymizer(self.token_map)

        # id → method for in-flight requests
        self._pending: dict[Any, str] = {}
        self._pending_lock = threading.Lock()

        # Protects writes to sys.stdout so both threads don't interleave
        self._stdout_lock = threading.Lock()

    def _write(self, msg: dict):
        line = json.dumps(msg, ensure_ascii=False) + "\n"
        with self._stdout_lock:
            sys.stdout.write(line)
            sys.stdout.flush()

    def _client_to_child(self, child_stdin):
        for raw_line in sys.stdin:
            try:
                msg = json.loads(raw_line)
            except json.JSONDecodeError:
                child_stdin.write(raw_line.encode())
                child_stdin.flush()
                continue

            method = msg.get("method", "")
            msg_id = msg.get("id")

            # Track this request so we can recognise the response
            if msg_id is not None and method:
                with self._pending_lock:
                    self._pending[msg_id] = method

            # Handle deanonymize locally — do not forward to child
            if method == "tools/call":
                tool_name = (msg.get("params") or {}).get("name", "")
                if tool_name == "deanonymize":
                    response = self._handle_deanonymize(msg)
                    self._write(response)
                    with self._pending_lock:
                        self._pending.pop(msg_id, None)
                    continue

            child_stdin.write(raw_line.encode())
            child_stdin.flush()

    def _child_to_client(self, child_stdout):
        for raw_line in child_stdout:
            try:
                msg = json.loads(raw_line)
            except (json.JSONDecodeError, ValueError):
                with self._stdout_lock:
                    sys.stdout.buffer.write(raw_line)
                    sys.stdout.flush()
                continue

            msg_id = msg.get("id")
            with self._pending_lock:
                method = self._pending.pop(msg_id, None) if msg_id is not None else None

            # Inject deanonymize into tools/list results
            if method == "tools/list" and "result" in msg:
                tools = msg["result"].get("tools", [])
                if not any(t.get("name") == "deanonymize" for t in tools):
                    tools.append(_DEANONYMIZE_TOOL)
                msg["result"]["tools"] = tools

            # Anonymize tools/call results
            elif method == "tools/call" and "result" in msg:
                content = msg["result"].get("content")
                if isinstance(content, list):
                    msg["result"]["content"] = self.anonymizer.anonymize_content_blocks(content)

            self._write(msg)

    def _handle_deanonymize(self, request: dict) -> dict:
        args = (request.get("params") or {}).get("arguments") or {}
        text = args.get("text", "")
        reverse = self.token_map.reverse_all()

        # Replace longest tokens first to avoid partial substitutions
        for token in sorted(reverse, key=len, reverse=True):
            text = text.replace(token, reverse[token])

        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [{"type": "text", "text": text}]
            }
        }

    def run(self):
        if not OPENSEARCH_WRAPPER.exists():
            sys.stderr.write(
                f"[anon-proxy] ERROR: opensearch-mcp.sh not found at {OPENSEARCH_WRAPPER}\n"
            )
            sys.exit(1)

        child = subprocess.Popen(
            [str(OPENSEARCH_WRAPPER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )

        t_in = threading.Thread(
            target=self._client_to_child,
            args=(child.stdin,),
            daemon=True,
        )
        t_out = threading.Thread(
            target=self._child_to_client,
            args=(child.stdout,),
            daemon=True,
        )
        t_in.start()
        t_out.start()

        t_in.join()
        child.stdin.close()
        t_out.join()
        child.wait()


if __name__ == "__main__":
    Proxy().run()
