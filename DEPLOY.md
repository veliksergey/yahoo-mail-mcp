# Deploying the bridge

The server is one Python process with no dependencies. Anywhere that can run
a small container, or Python 3.12, and give it an HTTPS address will do. This
page covers the steps that are the same everywhere, then the specifics for a
few budget-friendly hosts.

## What the host has to provide

| Requirement | Why |
| --- | --- |
| Always-on | Claude calls the server inside a tool call. A cold start of several seconds reads as a timeout, so a platform that sleeps idle services needs its always-on tier. |
| HTTPS | Claude connects to `https://` endpoints only. Most platforms terminate TLS for you; on a bare VPS, Caddy does it in three lines. |
| Reachable from Anthropic's network | Claude connects from Anthropic's cloud, not from your device. The default `ALLOW_CIDRS` is their [published egress range](https://platform.claude.com/docs/en/api/ip-addresses). |
| The caller's real address | Behind a proxy the socket peer is the proxy. `TRUSTED_IP_HEADER` names the header your proxy fills in from the connection. |
| About 256 MB of memory | The process is small; the headroom is for large messages. |

## Steps that are the same everywhere

### 1. Generate a Yahoo app password

Yahoo account, **Account Security**, **Generate app password**. Any name will
do. The server only ever sees this password, never the account password, and
you can revoke it at Yahoo at any moment.

### 2. Generate the URL token

```
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

That is `MCP_SECRET`. Your connector URL will be
`https://<your host>/mcp/<MCP_SECRET>`. Treat the URL as a password: it
lives in Claude's connector settings and nowhere else, least of all this
repository.

### 3. Set the environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `YAHOO_EMAIL` | yes | The mailbox address |
| `YAHOO_APP_PASSWORD` | yes | The app password from step 1 |
| `MCP_SECRET` | yes | The token from step 2 |
| `TRUSTED_IP_HEADER` | behind a proxy | The header your proxy fills in with the caller's address. See the per-host notes below |
| `YAHOO_FROM_NAME` | no | Display name on outgoing mail |
| `ALLOW_CIDRS` | no | Allowed caller ranges. Defaults to Anthropic's published range. `off` disables the filter |
| `PORT` | no | Listen port, default 8080 |

Every host has a place for these: secrets on Fly, variables in the Railway or
Render dashboard, a `.env` file next to the compose file on a VPS.

### 4. Add the connector to Claude

Claude settings, **Connectors**, **Add custom connector**. Paste the URL from
step 2. Choose no authentication: the token in the path and the address
filter are doing that job.

### 5. Check it

```
curl https://<your host>/health
{"status": "ok"}
```

The server's first log lines show what it believes about its surroundings:

```
yahoo-mail-bridge 1.1.0 listening on :8080
  mailbox     you@yahoo.com
  tools       10 (no delete; send and move each need confirming)
  ip filter   160.79.104.0/21
  ip header   Fly-Client-IP
```

If Claude reports that the connector cannot be reached while `/health` works,
look for `Rejected request from disallowed IP` in the log. A private address
there (`172.16.x.x`, `10.x.x.x`, `fdaa:...`) means the filter is seeing your
proxy instead of the caller, and `TRUSTED_IP_HEADER` needs setting.

## Fly.io

```
cp deploy/fly.toml.example fly.toml      # fly.toml is gitignored: it holds your hostname
flyctl apps create your-unique-name      # then set `app` in fly.toml to match
flyctl secrets set YAHOO_EMAIL="you@yahoo.com" YAHOO_APP_PASSWORD="..." MCP_SECRET="..." YAHOO_FROM_NAME="Your Name"
flyctl deploy
flyctl ips allocate-v4 --shared
```

The example config already sets `TRUSTED_IP_HEADER` to `Fly-Client-IP`,
keeps one machine always running, and points Fly's health check at `/health`.
Your URL is `https://your-unique-name.fly.dev/mcp/<MCP_SECRET>`.

`X-Forwarded-For` is the wrong header here: Fly appends the real address to
whatever the client sent, so its first entry is attacker-controlled.
`Fly-Client-IP` is written by the proxy itself.

## Any Docker host: Railway, Render, a VPS

The image is built from the `Dockerfile` with no arguments. On a platform,
point it at the repository, set the variables from step 3 in its dashboard,
and pick an always-on instance size. Then find out which header the
platform's router fills in with the connecting address and set
`TRUSTED_IP_HEADER` to it. If the only one on offer is `X-Forwarded-For`,
the server uses the last address in it, which is correct only when exactly
one proxy sits in front of you and it appends rather than overwrites. Check
the log line from step 5 after the first deploy.

On a VPS, `deploy/docker-compose.yml` runs the container bound to localhost
with a read-only filesystem:

```
cp deploy/env.example deploy/.env         # fill it in
docker compose -f deploy/docker-compose.yml up -d --build
```

and `deploy/Caddyfile.example` puts Caddy in front of it with automatic TLS.
Caddy overwrites `X-Real-IP` with the connection's address on every request,
which is why the example `.env` trusts that header.

## A machine at home behind a Cloudflare Tunnel

A tunnel gives a machine with no public address an HTTPS hostname without
opening a port. Run the container as above, then:

```
cloudflared tunnel --url http://127.0.0.1:8080
```

with the tunnel's hostname routed to it. Cloudflare sets `CF-Connecting-IP`
to the caller's address on every request, so `TRUSTED_IP_HEADER` is
`CF-Connecting-IP`. The container listens on localhost only, so nothing can
reach it except through the tunnel.

## When Anthropic's range changes

Set `ALLOW_CIDRS` to the new range, or to the old one plus the new addresses:

```
ALLOW_CIDRS="160.79.104.0/21,THE.NEW.IP/32"
```

A value that parses to nothing falls back to the default rather than
switching the filter off. Disabling it has to be spelled out as `off`.

## Rotating credentials

- **App password**: generate a new one at Yahoo, update the variable, restart,
  then revoke the old one at Yahoo.
- **URL token**: generate a new `MCP_SECRET`, update the variable, restart, and
  replace the connector URL in Claude. The old URL answers `404` from the
  moment the new process starts.
