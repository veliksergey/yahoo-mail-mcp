"""
Offline tests for server.py. No socket is opened and no mail is touched.

    python test_server.py
"""

import sys

from mailbox import MailboxError
from server import (
    TOOLS,
    client_ip,
    dispatch,
    ip_allowed,
    parse_cidrs,
    path_matches_secret,
    redact_token,
    secret_from_path,
    wants_sse,
)

CHECKS = 0
FAILURES = []


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILURES.append(label)


SECRET = "test-token-0123456789abcdefghijklmnopqrstuv"

DOCUMENTED_TOOLS = [
    "list_folders",
    "create_folder",
    "search_emails",
    "get_email",
    "move_emails",
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

check(
    client_ip({"Fly-Client-IP": "160.79.104.5"}, "172.16.0.1") == "160.79.104.5",
    "Fly-Client-IP is used when present",
)
check(client_ip({}, "172.16.0.1") == "172.16.0.1", "the socket peer is the last resort")
check(
    client_ip({"X-Forwarded-For": "160.79.104.5"}, "203.0.113.9") == "203.0.113.9",
    "X-Forwarded-For is ignored -- its first entry is attacker controlled",
)
check(
    not ip_allowed(
        client_ip({"X-Forwarded-For": "160.79.104.5, 203.0.113.9"}, "203.0.113.9"), anthropic
    ),
    "a spoofed X-Forwarded-For cannot talk its way past the IP filter",
)

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
check(len(TOOLS) == 9, "there are exactly nine tools")
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
check(len(listed["result"]["tools"]) == 9, "tools/list returns all nine")

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
