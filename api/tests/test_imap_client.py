"""Task 11: pure-function and canned-FETCH tests for the IMAP client (no live server).

Fixture shapes follow REAL imaplib wire forms (D1 ruling):
- Literal-less summary FETCH: data entries are plain bytes lines like
  b'3 (UID 7 FLAGS (\\Seen) ... ENVELOPE (...))'.
- BODY.PEEK[] fetch: entry is a tuple (meta_line_bytes, literal_bytes).
The brief's original fixture passed a pre-parsed ENVELOPE python list as item[-1],
which imaplib never produces; expected_summary values are byte-identical to the brief.
"""
import base64
import pytest
from app.imap_client import xoauth2_string, parse_envelope_response, sanitize_query
from app.mail_models import MessageSummary

def test_xoauth2_string_encoding():
    raw = xoauth2_string("alice@x.y", "tok123")
    assert base64.b64decode(raw) == b"user=alice@x.y\x01auth=Bearer tok123\x01\x01"

def test_sanitize_query_strips_quotes():
    assert sanitize_query('foo"; DROP') == "foo DROP"
    # CR/LF stripped too: a TEXT query can never inject protocol lines (D4 ride-along).
    assert sanitize_query("foo\r\nbar") == "foobar"

def test_sanitize_query_strips_backslash_and_nul():
    assert sanitize_query("x\\") == "x"     # trailing backslash can't escape the quote
    assert sanitize_query("a\x00b") == "ab"  # NUL never reaches the wire

# Single plain-bytes line, exactly as imaplib returns for a summary FETCH with
# no literal (the trailing ')' closes the FETCH paren-list on the same line).
ENVELOPE_FETCH = (
    b"OK",
    [b'3 (UID 7 FLAGS (\\Seen) RFC822.SIZE 512 INTERNALDATE '
     b'"24-Aug-2026 10:00:00 +0000" ENVELOPE '
     b'("Mon, 24 Aug 2026 09:59:00 +0000" "Hello world" '
     b'((NIL NIL "alice" "sovereign.mail")) ((NIL NIL "alice" "sovereign.mail")) '
     b'((NIL NIL "alice" "sovereign.mail")) '
     b'(NIL NIL "bob" "sovereign.mail") NIL NIL NIL NIL))'],
)

def expected_summary() -> MessageSummary:
    return MessageSummary(uid=7, subject="Hello world", from_="alice@sovereign.mail",
                          to=["bob@sovereign.mail"], date="Mon, 24 Aug 2026 09:59:00 +0000",
                          seen=True, size=512)

def test_parse_envelope_response():
    got = parse_envelope_response(ENVELOPE_FETCH)[0]
    assert got == expected_summary()

def test_parse_envelope_response_tolerates_mixed_entries():
    # Tuple entry (meta line + ignored literal) followed by a None continuation
    # and the closing-paren line — parser must not crash (D4 ride-along).
    mixed = (
        b"OK",
        [(b'7 (UID 9 FLAGS () RFC822.SIZE 10 INTERNALDATE "24-Aug-2026 10:00:00 +0000" '
          b'ENVELOPE (NIL "S" ((NIL NIL "a" "b.c")) NIL NIL '
          b'((NIL NIL "d" "e.f")) NIL NIL NIL NIL)'),
         None,
         b")"],
    )
    rows = parse_envelope_response(mixed)
    assert len(rows) == 1
    row = rows[0]
    assert row["uid"] == 9
    assert row["subject"] == "S"
    assert row["from_"] == "a@b.c"
    assert row["to"] == ["d@e.f"]
    assert row["date"] is None   # NIL date stays None
    assert row["seen"] is False
    assert row["size"] == 10

def test_parse_envelope_response_flag_named_envelope_does_not_shadow():
    # A custom flag atom literally named ENVELOPE must not be taken for the
    # structure: the search is anchored on b"ENVELOPE (" so this row parses
    # instead of being silently dropped.
    shadowed = (
        b"OK",
        [b'5 (UID 11 FLAGS (\\Seen ENVELOPE) RFC822.SIZE 42 INTERNALDATE '
         b'"24-Aug-2026 10:00:00 +0000" ENVELOPE (NIL "S" ((NIL NIL "a" "b.c")) '
         b'NIL NIL ((NIL NIL "d" "e.f")) NIL NIL NIL NIL))'],
    )
    rows = parse_envelope_response(shadowed)
    assert len(rows) == 1 and rows[0]["subject"] == "S"

def test_parse_envelope_response_envelope_nil_skips_row():
    nil_env = (
        b"OK",
        [b'6 (UID 12 FLAGS () RFC822.SIZE 9 INTERNALDATE '
         b'"24-Aug-2026 10:00:00 +0000" ENVELOPE NIL)'],
    )
    assert parse_envelope_response(nil_env) == []

def test_seen_flag_restricted_to_flags_slice():
    # Subject text "C:\Seen" arrives as the IMAP-escaped quoted string
    # "C:\\Seen"; with an empty FLAGS slice the message must read UNSEEN even
    # though the byte sequence \Seen appears elsewhere on the meta line.
    tricky = (
        b"OK",
        [b'8 (UID 13 FLAGS () RFC822.SIZE 64 INTERNALDATE '
         b'"24-Aug-2026 10:00:00 +0000" ENVELOPE (NIL "C:\\\\Seen" '
         b'((NIL NIL "a" "b.c")) NIL NIL NIL NIL NIL))'],
    )
    row = parse_envelope_response(tricky)[0]
    assert row["seen"] is False and row["subject"] == "C:\\Seen"

FULL_MSG = (
    b"OK",
    [(b"7 (UID 7 BODY[] {86}", b"From: a@x.y\r\nTo: b@x.y\r\n"
      b'Subject: Hi\r\nContent-Type: multipart/mixed; boundary="BB"\r\n\r\n'
      b"--BB\r\nContent-Type: text/plain\r\n\r\nbody text\r\n--BB--"),
     None],
)

def test_read_parses_body():
    # Subscript (not attribute) access: ParsedMessage is a TypedDict — a plain dict
    # at runtime — matching how Task 12's router serializes it. The brief's test
    # used attribute access, which TypedDict cannot support.
    msg_bytes = FULL_MSG[1][0][1]
    from app.imap_client import parse_full_message
    parsed = parse_full_message(msg_bytes, summary=expected_summary())
    assert parsed["text_body"].strip() == "body text"
    assert parsed["summary"]["uid"] == 7
