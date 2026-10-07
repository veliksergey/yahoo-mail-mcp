# Contributing

Small project, few rules. Issues and pull requests are welcome.

## Running the tests

```
python test_mailbox.py
python test_server.py
```

Both run offline in under a second and need no credentials. CI runs them on
Python 3.12 and 3.13 and builds the container image.

## Rules that are structural

Three properties are enforced by the code and asserted by the tests. A change
that weakens any of them will not be merged, however convenient:

1. **No tool deletes mail.** "Delete" means a move to Trash. The IMAP commands
   that destroy mail as a side effect (`CLOSE`, a bare `EXPUNGE`, folder
   `DELETE` and `RENAME`) are never issued, and `test_mailbox.py` greps the
   source to prove it.
2. **Nothing is sent without a draft.** `send_draft` takes a uid and nothing
   else, so the send step cannot add a recipient or a line of text.
3. **Nothing moves without a preview.** `confirm_move` takes an id issued by
   `prepare_move` and nothing else, so the confirm step cannot widen what the
   user was shown.

Two more are about the process itself: the standard library only, and no
outbound HTTP, shell or file I/O anywhere in `server.py` or `yahoo_mailbox.py`. The
tests check for those too.

## Shape of the code

- Everything above `class Mailbox` in `yahoo_mailbox.py` is a pure function, and
  that is where new parsing or composing logic goes, with a check in
  `test_mailbox.py`.
- Tool descriptions are part of the security design. They tell the model what
  is untrusted and when to stop and ask. Edit them with that in mind.
- Comments explain *why*. The code already says what.

## Commits

Write the reasoning into the commit message. The history is meant to be read.
