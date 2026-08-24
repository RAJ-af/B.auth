"""IMAP client: XOAUTH2 sessions, envelope parsing, search, sent-append.

Wire-shape note (D1): imaplib returns FETCH data as either plain bytes meta lines
(literal-less summary fetch, e.g. b'3 (UID 7 FLAGS (\\Seen) ... ENVELOPE (...))') or
tuples (meta_line_bytes, literal_bytes) for BODY.PEEK[] fetches. parse_envelope_response
accepts the raw data list in both shapes; a paren-aware tokenizer turns the ENVELOPE
structure into Python values (NIL -> None, integers -> int, quoted strings -> str).

Documented limitation (Phase 2): non-ASCII header values arrive as {n} literals on the
wire; this parser does not consume IMAP literals inside ENVELOPE — lab traffic is ASCII.
"""
# Lazy annotations: MailSession defines a method named `list`, which shadows the
# builtin inside the class body; on Python <=3.13 eager annotation evaluation makes
# `-> list[...]` on later methods raise TypeError ('function' object is not
# subscriptable). Verified empirically on py3.12; py3.14+ (PEP 649 default) hides it.
from __future__ import annotations

import asyncio
import base64
import email
import imaplib
import logging
import ssl
from email.header import decode_header, make_header

from .mail_models import MessageSummary, ParsedMessage
from .config import get_settings

log = logging.getLogger(__name__)

class DownstreamError(Exception): pass

FOLDER_ALLOWLIST = {"INBOX", "Sent"}
PAGE_DEFAULT_LIMIT = 50

def xoauth2_string(username: str, access_token: str) -> bytes:
    raw = f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()
    return base64.b64encode(raw)

def sanitize_query(q: str) -> str:
    # Strip quotes and semicolons plus CR/LF so a TEXT search can neither break out
    # of the quoted SEARCH key nor inject protocol lines (test is the contract).
    for ch in ('"', ";", "\r", "\n"):
        q = q.replace(ch, "")
    return q.strip()

def _dec(value) -> str:
    if value is None: return ""
    if isinstance(value, bytes): value = value.decode("utf-8", "replace")
    try: return str(make_header(decode_header(value)))
    except Exception: return value

def _addr_tuple_to_str(addr) -> str | None:
    if not addr: return None
    _, _, mbox, host = addr[0]
    return f"{mbox}@{host}" if mbox and host else None

def _addr_list(addr) -> list[str]:
    """Flatten an ENVELOPE address field to a list of "mailbox@host".

    Tolerates both observed shapes: a list of address groups ((name adl mbox host))
    and, as some producers emit for single-address fields (incl. the brief's own
    fixture), one bare 4-tuple group — normalized here before parsing."""
    if not addr: return []
    groups = [addr] if not isinstance(addr[0], (list, tuple)) else addr
    return [s for s in (_addr_tuple_to_str([g]) for g in groups) if s]

def _tokenize_imap_parens(data: bytes, pos: int = 0) -> tuple[list, int]:
    """Tokenize one parenthesized IMAP structure starting at data[pos] == b'('.

    Handles nested parens and double-quoted strings with backslash escapes.
    Values: NIL -> None, digit runs -> int, quoted strings -> str, atoms -> str.
    Returns (value, position just past the closing paren). Does NOT handle {n}
    literals (see module docstring limitation).
    """
    if data[pos:pos + 1] != b"(":
        raise ValueError("expected '('")
    pos += 1
    out: list = []
    while True:
        while pos < len(data) and data[pos:pos + 1] in b" \t\r\n":
            pos += 1
        ch = data[pos:pos + 1]
        if not ch:
            raise ValueError("unterminated IMAP list")
        if ch == b")":
            return out, pos + 1
        if ch == b"(":
            val, pos = _tokenize_imap_parens(data, pos)
            out.append(val)
        elif ch == b'"':
            pos += 1
            buf = bytearray()
            while True:
                c = data[pos:pos + 1]
                if not c:
                    raise ValueError("unterminated quoted string")
                if c == b"\\":
                    pos += 1
                    c = data[pos:pos + 1]
                elif c == b'"':
                    pos += 1
                    break
                buf += c
                pos += 1
            out.append(buf.decode("utf-8", "replace"))
        else:
            start = pos
            while pos < len(data) and data[pos:pos + 1] not in b' ()"':
                pos += 1
            atom = data[start:pos]
            if atom.upper() == b"NIL":
                out.append(None)
            elif atom.isdigit():
                out.append(int(atom))
            else:
                out.append(atom.decode("utf-8", "replace"))

def _envelope_from_meta(meta: bytes) -> list | None:
    """Locate and tokenize the ENVELOPE structure in a FETCH meta line."""
    i = meta.find(b"ENVELOPE ")
    if i < 0:
        return None
    j = i + len(b"ENVELOPE ")
    while j < len(meta) and meta[j:j + 1] in b" \t":
        j += 1
    if meta[j:j + 1] != b"(":   # ENVELOPE NIL or a {n} literal we don't consume
        return None
    val, _ = _tokenize_imap_parens(meta, j)
    return val

def parse_envelope_response(fetch_result) -> list[MessageSummary]:
    """Parse an imaplib FETCH result into MessageSummary rows.

    Accepts the raw data list exactly as imaplib returned it: plain-bytes meta
    lines and/or tuple entries whose item[0] is the meta line (item[1] literal is
    ignored); None / closing-paren continuation entries are skipped.
    Field indices follow RFC 3501 ENVELOPE order:
    [0]=date [1]=subject [2]=from [5]=to (address group = list of (name adl mailbox host)).
    """
    rows = []
    for item in fetch_result[1]:
        if isinstance(item, tuple):
            meta = item[0]
        elif isinstance(item, bytes):
            meta = item
        else:
            continue
        envelope = _envelope_from_meta(meta)
        if envelope is None or len(envelope) < 6:
            continue
        date = envelope[0]
        if isinstance(date, bytes):
            date = date.decode(errors="replace")
        rows.append(MessageSummary(
            uid=int(meta.split(b"UID ")[1].split()[0]),
            subject=_dec(envelope[1]),
            from_=_addr_tuple_to_str(envelope[2]),
            to=_addr_list(envelope[5]),
            date=date or None,
            seen=b"\\Seen" in meta,
            size=int(meta.split(b"RFC822.SIZE ")[1].split()[0]),
        ))
    return rows

def parse_full_message(raw: bytes, summary: MessageSummary) -> ParsedMessage:
    msg = email.message_from_bytes(raw)
    text_body = html_body = None
    attachments = []
    parts = msg.walk() if msg.is_multipart() else iter((msg,))
    for part in parts:
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "")
        if "attachment" in disp or part.get_filename():
            payload = part.get_payload(decode=True) or b""
            attachments.append({"name": part.get_filename() or "unnamed",
                                "type": ctype, "size": len(payload)})
        elif ctype == "text/plain" and text_body is None:
            text_body = (part.get_payload(decode=True) or b"").decode(
                part.get_content_charset() or "utf-8", "replace")
        elif ctype == "text/html" and html_body is None:
            html_body = (part.get_payload(decode=True) or b"").decode(
                part.get_content_charset() or "utf-8", "replace")
    return ParsedMessage(summary=summary,
                         headers={k: _dec(v) for k, v in msg.items()},
                         text_body=text_body, html_body=html_body,
                         attachments=attachments)

class MailSession:
    def __init__(self, username: str, access_token: str):
        s = get_settings()
        self.username, self.token = username, access_token
        self.host, self.port = s.imap_host, s.imap_port

    def __enter__(self):
        try:
            ctx = ssl.create_default_context(cafile=get_settings().ca_cert_path)
            self.conn = imaplib.IMAP4(self.host, self.port)
            self.conn.starttls(ssl_context=ctx)
            # imaplib.authenticate on current CPython (>=3.12 point releases, incl.
            # this container's 3.12.14) BASE64-ENCODES the authobject result itself
            # ("will be base64 encoded and sent" per its docstring; verified on the
            # wire: returning xoauth2_string() here went out double-encoded and
            # dovecot logged 'Username or token missing'). Hand it RAW bytes;
            # xoauth2_string remains the module's public b64 helper (tested).
            typ, _ = self.conn.authenticate(
                "XOAUTH2",
                lambda _: base64.b64decode(xoauth2_string(self.username, self.token)))
            if typ != "OK": raise DownstreamError(f"imap auth failed: {typ}")
        except DownstreamError: raise
        except Exception as e:
            raise DownstreamError(f"imap unavailable: {e}") from e
        return self

    def __exit__(self, *exc):
        try: self.conn.logout()
        except Exception: pass
        return False

    def _folder(self, folder: str) -> str:
        if folder not in FOLDER_ALLOWLIST: raise ValueError(f"folder not allowed: {folder}")
        return folder

    def list(self, folder: str = "INBOX", limit: int = PAGE_DEFAULT_LIMIT,
             offset: int = 0) -> tuple[int, list[MessageSummary]]:
        self._folder(folder)
        typ, data = self.conn.select(folder, readonly=True)
        if typ != "OK": raise DownstreamError(f"cannot select {folder}")
        typ, uids = self.conn.uid("SEARCH", None, "ALL")
        all_uids = uids[0].split() if uids and uids[0] else []
        total = len(all_uids)
        page = list(reversed(all_uids))[offset:offset + limit]   # newest first
        if not page: return total, []
        fetch_set = ",".join(u.decode() for u in page)
        typ, fetched = self.conn.uid("FETCH", fetch_set,
                                     "(FLAGS UID RFC822.SIZE INTERNALDATE ENVELOPE)")
        if typ != "OK": raise DownstreamError("fetch failed")
        rows = {r["uid"]: r for r in parse_envelope_response((typ, fetched))}
        return total, [rows[u] for u in sorted((int(x) for x in page)) if u in rows]

    def read(self, uid: int, folder: str = "INBOX") -> ParsedMessage:
        self._folder(folder)
        self.conn.select(folder)
        typ, fetched = self.conn.uid("FETCH", str(uid),
                                     "(FLAGS UID RFC822.SIZE INTERNALDATE ENVELOPE BODY.PEEK[])")
        if typ != "OK" or not fetched or not isinstance(fetched[0], tuple):
            raise DownstreamError(f"message {uid} not found")
        meta, raw = fetched[0][0], fetched[0][1]
        summaries = parse_envelope_response((typ, [(meta, None)]))
        summary = summaries[0] if summaries else MessageSummary(
            uid=uid, subject="", from_=None, to=[], date=None, seen=False, size=len(raw))
        self.conn.uid("STORE", str(uid), "+FLAGS", "(\\Seen)")   # read marks seen
        return parse_full_message(raw, summary)

    def search_text(self, folder: str, query: str) -> tuple[int, list[MessageSummary]]:
        self._folder(folder)
        self.conn.select(folder, readonly=True)
        q = sanitize_query(query)
        if not q: return 0, []
        typ, uids = self.conn.uid("SEARCH", None, "TEXT", f'"{q}"')
        found = uids[0].split() if uids and uids[0] else []
        total = len(found)
        page = list(reversed(found))[:PAGE_DEFAULT_LIMIT]
        if not page: return total, []
        typ, fetched = self.conn.uid("FETCH", ",".join(u.decode() for u in page),
                                     "(FLAGS UID RFC822.SIZE INTERNALDATE ENVELOPE)")
        rows = {r["uid"]: r for r in parse_envelope_response((typ, fetched))}
        return total, [rows[u] for u in sorted(int(x) for x in page) if u in rows]

    def append(self, folder: str, rfc822_bytes: bytes) -> None:
        try:
            self.conn.create(folder)
        except Exception: pass
        typ, _ = self.conn.append(f'"{folder}"', "", None, rfc822_bytes)
        if typ != "OK": raise DownstreamError(f"append to {folder} failed")

async def run_sync(fn, *args):
    return await asyncio.to_thread(fn, *args)
