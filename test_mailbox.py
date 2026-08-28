"""
Offline tests for mailbox.py. Never contacts Yahoo, needs no credentials.

    python test_mailbox.py
"""

import pathlib
import sys

from mailbox import (
    MailboxError,
    appenduid_from_response,
    as_address_list,
    as_uid_list,
    build_reply,
    build_search_criteria,
    decode_mailbox,
    encode_mailbox,
    extract_body,
    flags_from_meta,
    format_imap_date,
    header_str,
    list_attachments,
    parse_fetch_items,
    parse_list_line,
    parse_message,
    parse_status_line,
    quote_mailbox,
    recipients_of,
    reply_subject,
    strip_html,
    summarize,
    uid_from_meta,
)

CHECKS = 0
FAILURES = []


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILURES.append(label)


def check_raises(exc_type, fn, label):
    global CHECKS
    CHECKS += 1
    try:
        fn()
    except exc_type:
        return
    except Exception as exc:
        FAILURES.append(f"{label} -- raised {exc.__class__.__name__} instead")
        return
    FAILURES.append(f"{label} -- nothing was raised")


# --------------------------------------------------------------------------
# Modified UTF-7
# --------------------------------------------------------------------------

check(encode_mailbox("INBOX") == "INBOX", "plain ASCII survives encoding")
check(
    encode_mailbox("Projects/Alpha Site") == "Projects/Alpha Site",
    "nested ASCII folder needs no encoding",
)
check(encode_mailbox("A&B") == "A&-B", "a literal ampersand becomes &-")
check(decode_mailbox("&-") == "&", "&- decodes back to a literal ampersand")
check("&" in encode_mailbox("Ünread"), "non-ASCII triggers base64 encoding")
check(
    decode_mailbox(encode_mailbox("Договоры/Аренда")) == "Договоры/Аренда",
    "non-ASCII folder names round-trip",
)

# --------------------------------------------------------------------------
# Command quoting
# --------------------------------------------------------------------------

check(quote_mailbox("Projects/Alpha Site") == '"Projects/Alpha Site"', "folder names get quoted")
check(
    quote_mailbox('He said "hi"') == '"He said \\"hi\\""',
    "embedded quotes are escaped, not dropped",
)

# --------------------------------------------------------------------------
# LIST responses
# --------------------------------------------------------------------------

simple = parse_list_line(rb'(\HasNoChildren) "/" "INBOX"')
check(simple is not None and simple["name"] == "INBOX", "a basic LIST line yields its name")
check(simple is not None and simple["flags"] == ["\\HasNoChildren"], "LIST flags are split out")
check(simple is not None and simple["delimiter"] == "/", "the hierarchy delimiter is read")

spaced = parse_list_line(rb'(\HasChildren \Noselect) "/" "Projects/Alpha Site"')
check(
    spaced is not None and spaced["name"] == "Projects/Alpha Site",
    "quoted folder names keep their spaces",
)
check(parse_list_line(b"nonsense") is None, "an unparseable LIST line is skipped, not guessed at")

# --------------------------------------------------------------------------
# STATUS responses
# --------------------------------------------------------------------------

status = parse_status_line(rb'"INBOX" (MESSAGES 231 UNSEEN 4)')
check(status.get("MESSAGES") == 231, "STATUS message count parses as an integer")
check(status.get("UNSEEN") == 4, "STATUS unread count parses as an integer")
check(parse_status_line(b"garbage") == {}, "an unparseable STATUS line yields nothing")

# --------------------------------------------------------------------------
# FETCH responses
# --------------------------------------------------------------------------

fetched = [(b"1 (UID 4102 FLAGS (\\Seen))", b"Subject: Hi\r\n\r\n"), b")"]
items = parse_fetch_items(fetched)
check(len(items) == 1, "the stray b')' entries in a FETCH response are ignored")
check(items[0][1].startswith(b"Subject:"), "the message literal is returned intact")
check(uid_from_meta(b"1 (UID 4102 FLAGS (\\Seen))") == "4102", "the UID is read from the metadata")
check(
    flags_from_meta(b"1 (UID 4102 FLAGS (\\Seen \\Answered))") == ["\\Seen", "\\Answered"],
    "flags are read from the metadata",
)

# --------------------------------------------------------------------------
# Dates and search
# --------------------------------------------------------------------------

check(format_imap_date("2026-08-28") == "28-Aug-2026", "ISO dates convert to the IMAP form")
check_raises(MailboxError, lambda: format_imap_date("28/08/2026"), "a non-ISO date is rejected")
check_raises(MailboxError, lambda: format_imap_date("2026-13-01"), "month 13 is rejected")

check(build_search_criteria() == "ALL", "an empty search asks for ALL")
check(
    build_search_criteria(unread_only=True) == "(UNSEEN)",
    "unread_only becomes the UNSEEN key",
)
check(
    build_search_criteria(sender="bob@example.com") == '(FROM "bob@example.com")',
    "a sender filter is quoted",
)
check(
    build_search_criteria(query="easement", since="2026-08-01")
    == '(TEXT "easement" SINCE 01-Aug-2026)',
    "text and date filters combine in one key",
)
check(
    build_search_criteria(query='plat"\r\nA1 LOGOUT') == '(TEXT "plat\\"A1 LOGOUT")',
    "a CRLF in a search term cannot end the IMAP command and start a new one",
)
check(
    "\r" not in quote_mailbox("Deals\r\nA1 LOGOUT")
    and "\n" not in quote_mailbox("Deals\r\nA1 LOGOUT"),
    "a CRLF in a folder name cannot break out of the quoted string",
)

# --------------------------------------------------------------------------
# HTML flattening
# --------------------------------------------------------------------------

check(strip_html("<p>Hello <b>there</b></p>") == "Hello there", "tags are stripped")
check(
    "alert" not in strip_html("<script>alert(1)</script><p>Safe</p>"),
    "script contents are removed, not just their tags",
)
check(strip_html("<p>Tom &amp; Jerry</p>") == "Tom & Jerry", "HTML entities are unescaped")

# --------------------------------------------------------------------------
# Reading real messages
# --------------------------------------------------------------------------

PLAIN = (
    b"From: Victor <victor@example.com>\r\n"
    b"To: alice@example.com\r\n"
    b"Subject: =?utf-8?B?RWFzZW1lbnQgcGxhdA==?=\r\n"
    b"Date: Fri, 28 Aug 2026 09:00:00 -0400\r\n"
    b"Message-ID: <abc123@example.com>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"The surveyor sent the revised plat.\r\n"
)

HTML_ONLY = (
    b"From: Clerk <clerk@example.com>\r\n"
    b"To: alice@example.com\r\n"
    b"Subject: Recording\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><p>Bring <b>two</b> copies.</p></body></html>\r\n"
)

WITH_ATTACHMENT = (
    b"From: Surveyor <survey@example.com>\r\n"
    b"To: alice@example.com\r\n"
    b"Subject: Plat\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="EDGE"\r\n'
    b"\r\n"
    b"--EDGE\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Attached.\r\n"
    b"--EDGE\r\n"
    b"Content-Type: application/pdf\r\n"
    b"Content-Disposition: attachment; filename=\"plat.pdf\"\r\n"
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"JVBERi0xLjQK\r\n"
    b"--EDGE--\r\n"
)

plain_msg = parse_message(PLAIN)
check(
    extract_body(plain_msg).strip() == "The surveyor sent the revised plat.",
    "a plain-text body is read verbatim",
)
check(
    extract_body(parse_message(HTML_ONLY)).strip() == "Bring two copies.",
    "an HTML-only body falls back to flattened text",
)
check(
    header_str(plain_msg, "Subject") == "Easement plat",
    "an RFC 2047 encoded subject is decoded",
)

attachments = list_attachments(parse_message(WITH_ATTACHMENT))
check(
    [a["filename"] for a in attachments] == ["plat.pdf"],
    "attachment filenames are listed",
)
check(
    summarize(plain_msg, "7", "INBOX", ["\\Seen"])["unread"] is False,
    "a message flagged \\Seen is not reported as unread",
)

# --------------------------------------------------------------------------
# Composing
# --------------------------------------------------------------------------

check(
    as_address_list("a@x.com, b@y.com") == ["a@x.com", "b@y.com"],
    "a comma-separated recipient string splits into a list",
)
check(
    appenduid_from_response([b"[APPENDUID 1568231 4102] APPEND completed"]) == "4102",
    "the UID of a saved draft is read from the APPENDUID response",
)
check(
    as_uid_list("4102, 4103 4104") == ["4102", "4103", "4104"]
    and as_uid_list(["4102", 4103]) == ["4102", "4103"]
    and as_uid_list(4102) == ["4102"],
    "UIDs are accepted as a list, a bare value, or one delimited string",
)
check_raises(
    MailboxError, lambda: as_uid_list("not-a-uid"), "a non-numeric UID is rejected clearly"
)
check(
    as_uid_list('["496394"]') == ["496394"]
    and as_uid_list('["496394", "496395"]') == ["496394", "496395"],
    "a UID array sent as JSON text is recovered, not refused",
)
check(
    as_address_list('["a@x.com", "b@y.com"]') == ["a@x.com", "b@y.com"],
    "a recipient array sent as JSON text is recovered too",
)

bcc_msg = parse_message(
    b"To: a@x.com\r\nCc: b@y.com\r\nBcc: c@z.com, A@X.COM\r\nSubject: x\r\n\r\nhi\r\n"
)
check(
    recipients_of(bcc_msg) == ["a@x.com", "b@y.com", "c@z.com"],
    "a draft's real recipients include Bcc and are deduplicated",
)
check(reply_subject("Plat revision") == "Re: Plat revision", "replies gain a Re: prefix")
check(reply_subject("Re: Plat revision") == "Re: Plat revision", "Re: is never doubled up")

reply = build_reply(plain_msg, "Got it, thanks.", "alice@example.com", "Alice")
check(
    reply["In-Reply-To"] == "<abc123@example.com>"
    and "> The surveyor sent the revised plat." in reply.get_content(),
    "a reply threads to the original and quotes it",
)


# --------------------------------------------------------------------------
# Nothing may permanently destroy mail. These two IMAP calls do it as a side
# effect, silently and beyond the UIDs we asked about, so neither may appear.
# --------------------------------------------------------------------------

SOURCE = pathlib.Path(__file__).with_name("mailbox.py").read_text(encoding="utf-8")

check(
    "conn.expunge()" not in SOURCE,
    "no bare EXPUNGE: it would remove every \\Deleted message in the folder",
)
check(
    "self.conn.close()" not in SOURCE and "conn.unselect()" in SOURCE,
    "sessions end with UNSELECT, never CLOSE, which expunges on the way out",
)
check(
    "conn.delete(" not in SOURCE and "conn.rename(" not in SOURCE,
    "no folder can be deleted or renamed: those commands are never issued",
)
check(
    not any(
        risky in SOURCE
        for risky in ("urllib", "http.client", "requests.", "subprocess", "os.system")
    ),
    "no outbound HTTP or shell: mail cannot be posted anywhere but Yahoo's SMTP",
)


# --------------------------------------------------------------------------

print(f"test_mailbox.py: {CHECKS} checks, {len(FAILURES)} failed")
for failure in FAILURES:
    print("  FAIL:", failure)
sys.exit(1 if FAILURES else 0)
