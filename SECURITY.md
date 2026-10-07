# Security policy

## What this server is

A process that holds an app password for a Yahoo mailbox, reads mail with it,
and can put mail on the wire through Yahoo's SMTP. The design goal is a
bounded worst case rather than a perfect one: the server has no way to delete
mail, no single tool call can both choose a mailbox change and perform it, and
the only path out of the process is an approved draft. The README's *Design
notes* and *Threat model* sections say exactly what is and is not enforced.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: the **Security** tab of
this repository, then **Report a vulnerability**. If that option is not
available to you, open an issue that says only that you have a security
report, with no details, and I will set up a private channel.

You can expect an acknowledgement within a week. This is a personal project
maintained in spare time, so fixes land as quickly as I can get to them. I am
glad to credit reporters in the fix unless you would rather I did not.

## What I most want to hear about

- Any way a single tool call can both decide what happens to the mailbox and
  make it happen, or a way for the confirm step to act on more than the
  prepare step showed.
- Any way to send mail without a draft that already exists, or to change a
  draft between its creation and `send_draft` other than through Yahoo's own
  apps.
- Any path for mail content to leave the process other than Yahoo's SMTP.
- Any way to permanently destroy mail: an expunge, a folder delete, a rename.
- A bypass of the address filter or the URL token, including header spoofing
  on a documented hosting setup, timing differences in the token comparison,
  or the token reaching a log.
- IMAP or SMTP command injection through tool arguments, which an email's
  contents can influence.

## Out of scope

- Prompt injection against the model itself. The server marks message content
  as untrusted and bounds what any one call can do, but it cannot verify that
  a human approved the gap between a prepare call and a confirm call. The
  README documents this as the residual risk.
- Denial of service and rate limiting, which the README lists as not
  implemented. The address filter and the token are the whole defence.
- Yahoo's own services and infrastructure.

## Supported versions

Only the `main` branch. There are no releases to backport to.

## If you run one of these

- Rotate the Yahoo app password at Yahoo, and `MCP_SECRET` in your host's
  environment, whenever you suspect either has been seen. Both take effect
  on restart, and the old app password stops working the moment you revoke it.
- Keep `ALLOW_CIDRS` current with Anthropic's published range.
- Treat the connector URL as a password. The server redacts it from its own
  logs; keep it out of yours.
