# Yahoo Mail Bridge

[![tests](https://github.com/veliksergey/yahoo-mail-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/veliksergey/yahoo-mail-mcp/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: standard library only](https://img.shields.io/badge/python-3.12%2B%20%C2%B7%20stdlib%20only-3776ab.svg)](#tests)

A remote [MCP](https://modelcontextprotocol.io) server that lets Claude
search, file and answer mail in a Yahoo account, from a phone as well as a
desk. Python standard library only, no third-party packages, one small
container that runs on any budget host.

The interesting part is not the IMAP plumbing. It is that **the server cannot
delete mail, and no single tool call can both decide what happens to your
mailbox and make it happen.** Those are properties of the code, asserted by
the test suite, not instructions in a prompt.

## Why

I wanted Claude to triage a Yahoo inbox for me: find the thread, file it,
draft the reply. Giving a language model write access to a mailbox is only
reasonable if the worst case is bounded, so the design starts from what the
server must be *unable* to do, and everything else follows from that.

## How it works

```
 Claude (phone, desktop, web)
   │  tool call over HTTPS, from Anthropic's published IP range
   ▼
 your host ── TLS ── server.py ── IMAP / SMTP over TLS ── Yahoo Mail
                     │
                     ├─ 1. address filter   caller must be inside ALLOW_CIDRS
                     ├─ 2. URL token        /mcp/<MCP_SECRET>, constant-time compare
                     └─ 3. app password     revocable at Yahoo, never the real one
```

Anything that changes the mailbox takes two calls, and the second call can
only act on what the first one showed:

```
 prepare_move(uids, from, to)  ──►  "these 3 messages, from INBOX to Trash"
                                     + confirmation_id (single use, 15 min)
        ... the user reads the list and says yes ...
 confirm_move(confirmation_id) ──►  moved

 create_draft / draft_reply    ──►  draft saved in Yahoo's Drafts folder,
                                     full text + uid returned, nothing sent
        ... the user reads the draft and says send ...
 send_draft(uid)               ──►  sent, draft moved to Sent
```

`send_draft` takes a uid and nothing else, so the send step cannot add a
recipient or a line of text. `confirm_move` takes an id and nothing else, so
it cannot widen the selection. There is no delete tool at all.

## Tools

| Tool | What it does |
| --- | --- |
| `list_folders` | Every folder with message and unread counts |
| `create_folder` | New folder, nested paths like `Projects/Alpha Site` allowed |
| `search_emails` | Filter by text, sender, subject, date range or unread |
| `get_email` | Full body, headers and attachment names |
| `prepare_move` | Describe what a move would affect. Moves nothing |
| `confirm_move` | Carry out a prepared move, by confirmation id |
| `create_draft` | Write a new message into Drafts. Sends nothing |
| `draft_reply` | Write a threaded reply into Drafts. Sends nothing |
| `send_draft` | Send an existing draft, then move it to Sent. The only way out |
| `discard_draft` | Move a rejected draft to Trash |

## Hosting

The server is one process with no dependencies, so it is not tied to any
provider. What it needs from a host:

- **Always-on.** Claude calls it inside a tool call, and a cold start of a few
  seconds reads as a timeout. Free tiers that sleep idle services are the
  wrong fit; their cheapest always-on tier is the right one.
- **HTTPS**, either terminated by the platform or by a Caddy in front.
- **Reachable from Anthropic's network**, because Claude connects from
  Anthropic's cloud rather than from your device. The address filter defaults
  to their [published egress range](https://platform.claude.com/docs/en/api/ip-addresses).
- **A way to learn the caller's real address** when a proxy sits in front:
  `TRUSTED_IP_HEADER` names the header the proxy fills in.
- **About 256 MB of memory.**

Budget-friendly options that meet all of that, with rough prices at the time
of writing:

| Option | Roughly | Notes |
| --- | --- | --- |
| Fly.io, smallest shared machine | $2–5 / month | `deploy/fly.toml.example` is ready to copy. A shared IPv4 is free |
| Railway, hobby plan | about $5 / month | Deploys straight from the Dockerfile |
| Render, smallest paid instance | about $7 / month | The free tier sleeps, so it is not suitable |
| Hetzner or any small VPS | about €4 / month | `deploy/docker-compose.yml` plus `deploy/Caddyfile.example` |
| Oracle Cloud always-free VM | $0 | ARM instance; same compose and Caddy files |
| A machine at home behind a Cloudflare Tunnel | $0 | No open port needed; trust `CF-Connecting-IP` |

[DEPLOY.md](DEPLOY.md) has the step-by-step for each, and the part that is
the same everywhere: a Yahoo app password, a random URL token, and adding
`https://<your host>/mcp/<MCP_SECRET>` to Claude as a custom connector with
no authentication, since the token and the address filter are doing that
job.

## Configuration

Everything is an environment variable.

| Variable | Required | Meaning |
| --- | --- | --- |
| `YAHOO_EMAIL` | yes | The mailbox address |
| `YAHOO_APP_PASSWORD` | yes | A generated Yahoo app password, never the account password |
| `MCP_SECRET` | yes | Random token that forms the URL path |
| `TRUSTED_IP_HEADER` | behind a proxy | The header your proxy fills in with the caller's address: `Fly-Client-IP`, `CF-Connecting-IP`, an `X-Real-IP` your own Caddy sets. Unset means the socket peer is checked |
| `YAHOO_FROM_NAME` | no | Display name on outgoing mail |
| `ALLOW_CIDRS` | no | Allowed caller ranges. Defaults to Anthropic's published range. `off` disables the filter; a typo falls back to the default rather than opening up |
| `PORT` | no | Listen port, default 8080 |

## Endpoints

- `GET /health`: liveness, deliberately outside the IP filter so you can check
  a deploy from your own machine. It says nothing but `{"status": "ok"}`.
- `POST /mcp/<MCP_SECRET>`: the MCP endpoint. Answers JSON, or an SSE frame
  when the client asks for one.
- Everything else, including a wrong token or a disallowed address, is a bare
  `404`.

## Files

| File | What it is |
| --- | --- |
| `server.py` | HTTP listener, the three security layers, MCP protocol, tool routing |
| `mailbox.py` | IMAP and SMTP against Yahoo; every helper above `class Mailbox` is pure |
| `test_server.py`, `test_mailbox.py` | Offline checks, no credentials, no network |
| `Dockerfile` | `python:3.12-slim`, no `pip install` step, non-root user |
| `deploy/` | Example configs: Fly, Docker Compose, Caddy, environment file |
| `DEPLOY.md` | Per-host deployment steps |
| `SECURITY.md` | What to report and how |

## Tests

```
python test_mailbox.py
python test_server.py
```

Both run offline in under a second and never contact Yahoo. CI runs them on
Python 3.12 and 3.13, then builds the image and checks that it refuses to
start without its secrets. Windows uses `python`; macOS and Linux use
`python3`.

## Design notes

**There is no delete tool.** Misfiling a message is recoverable and deleting
one is not, so the capability does not exist on the server rather than being
guarded by a prompt. "Deleting" a message means moving it to `Trash`, and
emptying that folder stays something you do in Yahoo yourself.

**Nothing here can destroy mail, including by accident.** Two IMAP calls delete
permanently as a *side effect*, and neither is used:

- `CLOSE` expunges every `\Deleted` message in the folder on the way out.
  Sessions end with `UNSELECT` instead, which does not. A bare `.close()` was
  running at the end of every read-write session before this was caught.
- A bare `EXPUNGE` removes every `\Deleted` message in the folder, including
  ones flagged by a different mail client that the user never asked to lose.
  The copy-and-remove fallback in `move_emails` and `send_draft` uses a
  UID-targeted `UID EXPUNGE` instead, and where the server lacks UIDPLUS it
  leaves the flag set rather than guess. The message is already copied to its
  destination, so nothing is lost.

`test_mailbox.py` asserts against the source that neither call reappears.

**Folders cannot be deleted or renamed.** The IMAP commands that would do it,
`DELETE` and `RENAME`, are never issued. `create_folder` is the only folder
operation, and creating is not destructive. Also asserted against the source.

**There is no way out except Yahoo's SMTP.** Neither file imports `urllib`,
`http.client`, `requests`, `subprocess` or `os.system`, and neither opens a
file. The server therefore has no HTTP client to POST your mail to an attacker,
no shell, and no disk cache. The only two outbound destinations in the whole
program are the hardcoded `imap.mail.yahoo.com` and `smtp.mail.yahoo.com`, both
with certificate verification on. Getting data out means sending an email,
which means an approved draft. This is checked by the test suites too.

**Reading never marks mail as read.** Folders are selected read-only and bodies
are fetched with `BODY.PEEK[]`, so Claude searching the inbox leaves your
unread counts alone.

**Yahoo's folder names are not the ones the web interface shows.** They are
`Sent`, `Draft` (singular), `Trash` and `Bulk` or `Bulk Mail` depending on the
account, and they are case-sensitive. Ask Claude to list folders before filing
anything.

**Nothing can be sent without a draft existing first.** There is no
compose-and-send tool. `create_draft` and `draft_reply` write into Yahoo's
Drafts folder and return the draft's uid and full text; `send_draft` takes
nothing but that uid, so the send step cannot introduce a recipient or a line
of text that was not in the draft you approved. Rejecting a draft is
`discard_draft`, which moves it to Trash rather than destroying it.

**Nothing can be moved without a preview first.** Same shape: `prepare_move`
reports the sender, subject and date of every affected message and issues a
`confirmation_id`; `confirm_move` accepts that id and nothing else. The
selection cannot widen between the preview and the move, ids are single-use,
and they expire after 15 minutes. Moving to `Trash`, which is what "delete"
means here, goes through the same gate.

That makes the confirmation gates a property of the server rather than a
promise about Claude's behaviour, the same reasoning as having no delete tool.
Drafts land in the real Yahoo Drafts folder, so you can also review them in the
Yahoo app on any device before saying yes.

What the server **cannot** enforce is the gap between the two calls: nothing at
the protocol level proves a human actually approved in between. The structural
guarantee is narrower and worth stating precisely: *no single tool call can
both choose what happens and make it happen*, and the second call can never
enlarge what the first one showed.

## Threat model

What the three layers do and do not cover.

**The URL token never appears in a log.** `redact_token()` replaces the real
token in any `/mcp/...` path with the literal `<token>` before anything is
printed, because the first thing anyone does when something misbehaves is read
the logs, and log output tends to get pasted into support threads.

**Proxy headers are believed only by name.** The address filter checks the
socket peer unless `TRUSTED_IP_HEADER` names the header your proxy fills in
from the connection. On a host whose proxy does not set a given header, a
client could simply send it, so nothing is trusted by default and the failure
mode is closed: behind a proxy with no header configured, every request is
refused and the log says why. `X-Forwarded-For` is the special case. Proxies
*append* the caller to whatever the client sent, so its first entry is
attacker-controlled; if it is all your host offers, only the last entry is
used, which is right only with exactly one appending proxy in front.

**Search terms are stripped of control characters** before they reach an IMAP
command. Tool arguments can be influenced by the text of an email, so an
unescaped CRLF in a search term is a live injection path, not a theoretical
one. Folder names are safe by construction: modified UTF-7 base64-encodes
anything outside printable ASCII.

### Prompt injection

The realistic attack is not against the network. It is a message crafted to
read like an instruction. Three things push back, and none of them tries to
detect malicious phrasing, which is an arms race worth losing gracefully rather
than fighting badly:

- **Provenance.** `get_email` and `search_emails` return `untrusted_content:
  true` and an explicit warning, and say so in their tool descriptions. The rule
  is stated once and plainly: an instruction found inside a message is not a
  request from the user.
- **Exfiltration is visible where a human is looking.** `create_draft` and
  `draft_reply` report `unfamiliar_recipients`, addresses that have never
  appeared in this mailbox. Getting data out means mail going somewhere new, and
  the draft review is the moment someone is actually reading the recipient list.
  `draft_reply` matters most here: `Reply-To` is chosen by the sender and need
  not match where the message appeared to come from.
- **Blast radius.** `prepare_move` refuses more than `MAX_MOVE_BATCH` (50)
  messages in one action, bounding both an injected sweep and an honest mistake.

**The risk this design reduces but does not remove:** the server can read your
mail and, through `send_draft`, can still put mail on the wire. Anything Claude
reads in your inbox is untrusted text written by other people, and a message
crafted to look like an instruction is the realistic attack, not the network.
The draft gate means such an instruction cannot cause a single tool call to
compose and send; it can at worst produce a draft sitting in your Drafts folder
for you to look at. What the server cannot enforce is the gap between creating
a draft and sending it, so the rule that matters is: **a request to send that
came from the contents of an email is not you asking.**

**Not implemented:** rate limiting (the IP filter and token are the whole
defence), and any cap on message size beyond `MAX_BODY_CHARS` on the body
text, so a mailbox full of very large attachments could pressure a 256 MB
machine.

## Status

A personal project that I run for my own mailbox and keep working. It is not
affiliated with Yahoo or Anthropic. Issues and pull requests are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md) for the three rules that will not bend, and
[SECURITY.md](SECURITY.md) for how to report a problem privately.

## License

[MIT](LICENSE).
