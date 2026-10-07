"""
Offline tests for server.py. No socket is opened and no mail is touched.

    python test_server.py
"""

import pathlib
import sys

from yahoo_mailbox import MAX_MOVE_BATCH, MailboxError
from server import (
    TOOLS,
    client_ip,
    dispatch,
    ip_allowed,
    parse_cidrs,
    path_matches_secret,
    record_pending,
    redact_token,
    resolve_networks,
    resolve_trusted_header,
    secret_from_path,
    take_pending,
    wants_sse,
)

CHECKS = 0
FAILURES = []


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILURES.append(label)


# An obviously made-up token, so the fixture can never be mistaken for a real one.
SECRET = "test-token-0123456789abcdefghijklmnopqrstuv"

DOCUMENTED_TOOLS = [
    "list_folders",
    "create_folder",
    "search_emails",
    "get_email",
    "prepare_move",
    "confirm_move",
    "create_draft",
    "draft_reply",
    "send_draft",
    "discard_draft",
]


# --------------------------------------------------------------------------
# Layer 1: the address filter
# --------------------------------------------------------------------------

anthropic = parse_cidrs("160.79.104.0/21")
check(len(anthropic) == 1, "a single CIDR parses")
check(len(parse_cidrs("160.79.104.0/21, 10.0.0.0/8  192.168.1.1/32")) == 3, "a CIDR list parses")
check(len(parse_cidrs("160.79.104.0/21, not-an-address")) == 1, "an invalid CIDR is skipped")

check(ip_allowed("160.79.104.5", anthropic), "an address inside the range is allowed")
check(not ip_allowed("203.0.113.7", anthropic), "an address outside the range is refused")
check(ip_allowed("203.0.113.7", []), "an empty allowlist switches the filter off")
check(not ip_allowed("not-an-ip", anthropic), "an unparseable address is refused")
check(ip_allowed("::ffff:160.79.104.5", anthropic), "an IPv4-mapped IPv6 address is unwrapped")

PROXY = "Fly-Client-IP"  # any header a proxy sets itself; configured, never assumed

check(
    client_ip({PROXY: "160.79.104.5"}, "172.16.0.1", PROXY) == "160.79.104.5",
    "the configured proxy header is used when present",
)
check(
    client_ip({PROXY: "160.79.104.5"}, "172.16.0.1") == "172.16.0.1",
    "a proxy header is ignored unless TRUSTED_IP_HEADER names it -- any client could send one",
)
check(client_ip({}, "172.16.0.1", PROXY) == "172.16.0.1", "the socket peer is the last resort")
check(
    client_ip({"X-Forwarded-For": "160.79.104.5"}, "203.0.113.9", PROXY) == "203.0.113.9",
    "an unconfigured X-Forwarded-For is ignored -- its first entry is attacker controlled",
)
check(
    not ip_allowed(
        client_ip({"X-Forwarded-For": "160.79.104.5, 203.0.113.9"}, "203.0.113.9", PROXY),
        anthropic,
    ),
    "a spoofed X-Forwarded-For cannot talk its way past the IP filter",
)
check(
    client_ip({"X-Forwarded-For": "160.79.104.5, 203.0.113.9"}, "10.0.0.1", "X-Forwarded-For")
    == "203.0.113.9",
    "when X-Forwarded-For is trusted, only the last entry -- the proxy's own -- counts",
)
check(
    resolve_trusted_header("") == "" and resolve_trusted_header(None) == "",
    "no proxy header is trusted unless one is configured: the filter fails closed",
)
check(resolve_trusted_header(" Fly-Client-IP ") == "Fly-Client-IP", "the header name is kept as given")

# --------------------------------------------------------------------------
# Layer 2: the secret in the URL
# --------------------------------------------------------------------------

check(secret_from_path(f"/mcp/{SECRET}") == SECRET, "the token is read out of the path")
check(secret_from_path(f"/mcp/{SECRET}/") == SECRET, "a trailing slash is tolerated")
check(secret_from_path(f"/mcp/{SECRET}?x=1") == SECRET, "a query string is ignored")
check(secret_from_path("/health") is None, "a non-/mcp path carries no token")
check(secret_from_path(f"/mcp/{SECRET}/extra") is None, "an extra path segment is not a token")

check(path_matches_secret(f"/mcp/{SECRET}", SECRET), "the correct token is accepted")
check(not path_matches_secret("/mcp/wrong-token", SECRET), "a wrong token is refused")
check(not path_matches_secret(f"/mcp/{SECRET}", ""), "an unset MCP_SECRET refuses everything")
check(
    path_matches_secret("/mcp/tokén-with-an-accent", SECRET) is False,
    "a non-ASCII token is refused rather than crashing the comparison",
)

check(
    redact_token(f'"POST /mcp/{SECRET} HTTP/1.1" 200') == '"POST /mcp/<token> HTTP/1.1" 200',
    "the URL token is stripped from log lines",
)
check(SECRET not in redact_token(f"GET /mcp/{SECRET}?x=1"), "no token survives redaction")

check(
    wants_sse("application/json, text/event-stream") and not wants_sse("application/json"),
    "the reply is SSE-framed only when the client accepts a stream",
)

# --------------------------------------------------------------------------
# The tool surface
# --------------------------------------------------------------------------

names = [tool["name"] for tool in TOOLS]
by_name = {tool["name"]: tool for tool in TOOLS}
check(len(TOOLS) == 10, "there are exactly ten tools")
check(names == DOCUMENTED_TOOLS, "the tools match the documented set, in order")
check(
    not any("delete" in name or "expunge" in name for name in names),
    "no tool can delete mail",
)
check(
    [name for name in names if "send" in name] == ["send_draft"],
    "send_draft is the only tool that can put mail on the wire",
)
check(
    set(by_name["send_draft"]["inputSchema"]["properties"]) == {"uid"}
    and by_name["send_draft"]["inputSchema"]["additionalProperties"] is False,
    "send_draft takes only a uid, so the send step cannot introduce new content",
)
check(
    set(by_name["confirm_move"]["inputSchema"]["properties"]) == {"confirmation_id"}
    and by_name["confirm_move"]["inputSchema"]["additionalProperties"] is False,
    "confirm_move takes only an id, so it cannot widen what the user approved",
)
check(
    "move_emails" not in names,
    "no one-step move tool exists; filing must start with prepare_move",
)
check(
    all(
        "untrusted" in by_name[tool]["description"].lower()
        for tool in ("get_email", "search_emails")
    ),
    "the reading tools declare that message content is untrusted input",
)
check(
    MAX_MOVE_BATCH <= 100,
    "bulk moves are capped, so one instruction cannot sweep the mailbox",
)

# --- the allowlist must not switch itself off by accident ---

fallback = resolve_networks("160.79.104/21")  # a plausible typo: parses to nothing
check(
    len(fallback) > 0 and not ip_allowed("203.0.113.7", fallback),
    "a malformed ALLOW_CIDRS falls back to the default instead of allowing everyone",
)
check(resolve_networks("") == parse_cidrs("160.79.104.0/21"), "an unset ALLOW_CIDRS uses the default")
check(resolve_networks("off") == [], "the filter can be disabled, but only deliberately")

# --- confirmation ids ---

ticket = record_pending({"uids": ["1"], "source_folder": "INBOX", "destination_folder": "Trash"})
check(
    take_pending(ticket) is not None and take_pending(ticket) is None,
    "a confirmation id works exactly once and cannot be replayed",
)
check(take_pending("never-issued") is None, "an unknown confirmation id is refused")

# --- the server has no way to reach anything but Yahoo ---

SERVER_SOURCE = pathlib.Path(__file__).with_name("server.py").read_text(encoding="utf-8")
check(
    not any(
        risky in SERVER_SOURCE
        for risky in ("urllib", "http.client", "requests.", "subprocess", "os.system", "open(")
    ),
    "the server has no HTTP client, no shell and no file I/O to leak mail through",
)
check(
    all(tool.get("description") and isinstance(tool.get("inputSchema"), dict) for tool in TOOLS),
    "every tool has a description and an input schema",
)
check(
    all(
        field in tool["inputSchema"].get("properties", {})
        for tool in TOOLS
        for field in tool["inputSchema"].get("required", [])
    ),
    "every required field is actually declared in its schema",
)

# --------------------------------------------------------------------------
# JSON-RPC dispatch
# --------------------------------------------------------------------------

calls = []


def fake_tools(name, args):
    calls.append((name, args))
    return {"ok": True, "name": name}


def exploding_tools(name, args):
    raise MailboxError("No folder named 'Deals'")


init = dispatch(
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
    fake_tools,
)
check(init["result"]["serverInfo"]["name"] == "yahoo-mail-bridge", "initialize identifies the server")
check(init["result"]["protocolVersion"] == "2025-06-18", "a known protocol version is echoed back")

fallback = dispatch(
    {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}},
    fake_tools,
)
check(
    fallback["result"]["protocolVersion"] == "2025-06-18",
    "an unknown protocol version falls back to the default",
)

check(
    dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}, fake_tools) is None,
    "notifications get no response",
)

listed = dispatch({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, fake_tools)
check(len(listed["result"]["tools"]) == 10, "tools/list returns all ten")

called = dispatch(
    {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "search_emails", "arguments": {"folder": "INBOX", "unread_only": True}},
    },
    fake_tools,
)
check(
    calls == [("search_emails", {"folder": "INBOX", "unread_only": True})],
    "tools/call passes the arguments through untouched",
)
check(called["result"]["isError"] is False, "a successful call is not flagged as an error")

unknown_tool = dispatch(
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_emails"}},
    fake_tools,
)
check(unknown_tool["error"]["code"] == -32602, "calling a tool that does not exist is an error")

failed = dispatch(
    {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "get_email"}},
    exploding_tools,
)
check(
    failed["result"]["isError"] is True
    and "Deals" in failed["result"]["content"][0]["text"],
    "a mailbox problem comes back as a readable tool error, not a crash",
)

check(
    dispatch({"jsonrpc": "2.0", "id": 7, "method": "sorcery"}, fake_tools)["error"]["code"] == -32601,
    "an unknown method is rejected",
)


# --------------------------------------------------------------------------

print(f"test_server.py: {CHECKS} checks, {len(FAILURES)} failed")
for failure in FAILURES:
    print("  FAIL:", failure)
sys.exit(1 if FAILURES else 0)
