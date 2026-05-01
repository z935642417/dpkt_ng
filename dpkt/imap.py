# -*- coding: utf-8 -*-
"""IMAP4rev1 protocol parsing (RFC 3501)."""
from __future__ import absolute_import, print_function


class IMAPCommand(object):
    """IMAP command: tag SP verb SP args CRLF."""
    def __init__(self, raw=b''):
        self.tag = b''; self.verb = b''; self.args = b''
        if raw: self._parse(raw)

    def _parse(self, raw):
        line = raw.rstrip(b'\r\n')
        parts = line.split(b' ', 2)
        self.tag = parts[0] if len(parts) > 0 else b''
        self.verb = parts[1].upper() if len(parts) > 1 else b''
        self.args = parts[2] if len(parts) > 2 else b''

    def __repr__(self):
        return 'IMAPCommand(%s %s %s)' % (self.tag, self.verb, self.args[:50])

    def __bytes__(self):
        if self.args: return self.tag + b' ' + self.verb + b' ' + self.args + b'\r\n'
        return self.tag + b' ' + self.verb + b'\r\n'


class IMAPResponse(object):
    """IMAP response: tagged, untagged (*), or continuation (+).

    Tagged:   A001 OK LOGIN completed\r\n
    Untagged: * 1 FETCH (FLAGS (\\Seen))\r\n
    Cont:     + Ready for literal\r\n
    """
    def __init__(self, raw=b''):
        self.type = ''           # 'tagged', 'untagged', 'continuation'
        self.tag = b''           # tag (for tagged)
        self.status = b''        # OK/NO/BAD (for tagged/untagged status)
        self.text = b''          # text after status
        self.data = []           # parsed data items (for untagged)
        self.lines = []          # raw lines
        if raw: self._parse(raw)

    def _parse(self, raw):
        raw = raw.replace(b'\r\n', b'\n')
        if raw.endswith(b'\n'): raw = raw[:-1]
        self.lines = raw.split(b'\n')

        first = self.lines[0]
        if first.startswith(b'+'):
            self.type = 'continuation'
            self.text = first[1:].strip()
        elif first.startswith(b'*'):
            self.type = 'untagged'
            rest = first[2:].strip()
            parts = rest.split(b' ', 1)
            if parts and parts[0].isdigit():
                self._parse_untagged_data(first)
            elif parts and parts[0] in (b'OK', b'NO', b'BAD', b'PREAUTH', b'BYE'):
                self.status = parts[0]
                self.text = parts[1] if len(parts) > 1 else b''
            elif parts and parts[0] == b'SEARCH':
                self.data = parts[1].split() if len(parts) > 1 else []
            elif parts and parts[0] in (b'FLAGS', b'LIST', b'LSUB', b'STATUS', b'CAPABILITY', b'NAMESPACE', b'ENABLED'):
                self.text = rest
            elif parts and parts[0] in (b'EXISTS', b'RECENT', b'EXPUNGE'):
                self.text = rest
            else:
                self.text = rest
        else:
            self.type = 'tagged'
            parts = first.split(b' ', 2)
            self.tag = parts[0] if len(parts) > 0 else b''
            self.status = parts[1] if len(parts) > 1 else b''
            self.text = parts[2] if len(parts) > 2 else b''

    def _parse_untagged_data(self, first):
        """Parse untagged response like * 1 FETCH (...)"""
        rest = first[2:].strip()
        self.text = rest
        parts = rest.split(b' ', 2)
        if len(parts) >= 3:
            # * seq FETCH (...)
            atom = parts[1].upper()
            if atom == b'FETCH' and parts[2].startswith(b'('):
                self.data = _parse_imap_list(parts[2])

    def __repr__(self):
        t = self.type
        if t == 'tagged': return 'IMAPResponse(TAG %s %s)' % (self.tag, self.status)
        if t == 'untagged': return 'IMAPResponse(UNTAGGED %s)' % self.text[:50]
        return 'IMAPResponse(CONT %s)' % self.text[:50]

    def __bytes__(self):
        return b'\r\n'.join(self.lines) + b'\r\n'


def _parse_imap_list(data, start=0):
    """Parse parenthesized IMAP list (simplified). Returns list of items."""
    items = []
    i = 1  # skip opening '('
    buf = b''
    while i < len(data):
        c = data[i:i+1]
        if c == b')':
            if buf: items.append(buf); buf = b''
            return items
        elif c == b'(':
            sub, i = _parse_imap_sublist(data, i)
            items.append(sub)
        elif c == b' ':
            if buf: items.append(buf); buf = b''
            i += 1
        elif c == b'"':
            i += 1; quoted = b''
            while i < len(data) and data[i:i+1] != b'"':
                if data[i:i+1] == b'\\': i += 1
                quoted += data[i:i+1]; i += 1
            i += 1
            if buf: items.append(buf); buf = b''
            items.append(b'"' + quoted + b'"')
        elif c == b'{':
            i += 1; size_str = b''
            while i < len(data) and data[i:i+1] != b'}':
                size_str += data[i:i+1]; i += 1
            i += 1  # skip '}'
            # literal follows after \r\n
            if i < len(data) and data[i:i+1] == b'\r': i += 1
            if i < len(data) and data[i:i+1] == b'\n': i += 1
            lit_size = int(size_str) if size_str.isdigit() else 0
            if buf: items.append(buf); buf = b''
            items.append(b'{' + size_str + b'}' + data[i:i+lit_size])
            i += lit_size
        else:
            buf += c; i += 1
    if buf: items.append(buf)
    return items


def _parse_imap_sublist(data, start):
    """Parse nested sublist, return (items, new_offset)."""
    items = []; i = start + 1
    buf = b''
    while i < len(data):
        c = data[i:i+1]
        if c == b')':
            if buf: items.append(buf)
            return items, i + 1
        elif c == b'(':
            sub, i = _parse_imap_sublist(data, i)
            items.append(sub)
        elif c == b' ':
            if buf: items.append(buf); buf = b''
            i += 1
        elif c == b'"':
            i += 1; quoted = b''
            while i < len(data) and data[i:i+1] != b'"':
                if data[i:i+1] == b'\\': i += 1
                quoted += data[i:i+1]; i += 1
            i += 1
            if buf: items.append(buf); buf = b''
            items.append(b'"' + quoted + b'"')
        else:
            buf += c; i += 1
    if buf: items.append(buf)
    return items, i


class IMAPStreamParser(object):
    """Incremental IMAP stream parser with literal sync support."""
    def __init__(self):
        self.commands = []; self.responses = []
        self._buffer = b''; self._lit_pending = 0

    def feed(self, data):
        self._buffer += data
        self._process()

    def _process(self):
        while True:
            if self._lit_pending:
                if len(self._buffer) >= self._lit_pending:
                    self._buffer = self._buffer[self._lit_pending:]
                    self._lit_pending = 0
                else:
                    break  # wait for more literal data

            if b'\r\n' not in self._buffer: break

            idx = self._buffer.index(b'\r\n') + 2
            line = self._buffer[:idx]
            stripped = line.rstrip(b'\r\n')
            self._buffer = self._buffer[idx:]

            if not stripped: continue

            # Check for literal continuation
            if b'{' in stripped and b'}' in stripped and stripped.endswith(b'}'):
                s = stripped[stripped.index(b'{')+1:-1]
                if s.isdigit():
                    self._lit_pending = int(s)
                    # Store line and continue reading literal
                    self._pending_line = line
                    continue

            # Dispatch line
            if stripped.startswith(b'*') or stripped.startswith(b'+') or \
               (len(stripped.split(b' ', 1)) >= 2 and stripped.split(b' ', 1)[1][:2] in (b'OK', b'NO', b'BA')):
                resp = IMAPResponse(line)
                self.responses.append(resp)
            else:
                self.commands.append(IMAPCommand(line))


# ---- Tests ----
def test_imap_command():
    cmd = IMAPCommand(b'A001 SELECT INBOX\r\n')
    assert cmd.tag == b'A001'
    assert cmd.verb == b'SELECT'
    assert cmd.args == b'INBOX'
    assert bytes(cmd) == b'A001 SELECT INBOX\r\n'

def test_imap_response_tagged():
    rsp = IMAPResponse(b'A001 OK SELECT completed\r\n')
    assert rsp.type == 'tagged'
    assert rsp.tag == b'A001'
    assert rsp.status == b'OK'

def test_imap_response_untagged():
    rsp = IMAPResponse(b'* 1 EXISTS\r\n')
    assert rsp.type == 'untagged'
    assert b'EXISTS' in rsp.text

def test_imap_response_continuation():
    rsp = IMAPResponse(b'+ Ready for additional command text\r\n')
    assert rsp.type == 'continuation'
    assert b'Ready' in rsp.text

def test_imap_response_fetch():
    rsp = IMAPResponse(b'* 1 FETCH (FLAGS (\\Seen) BODY[] {5}\r\nHello)\r\n')
    assert rsp.type == 'untagged'
    assert len(rsp.lines) >= 1

def test_imap_list_parse():
    data = b'(FLAGS (\\Seen \\Answered) UID 123)'
    items = _parse_imap_list(data)
    assert len(items) >= 1

def test_imap_roundtrip():
    cmd = IMAPCommand(b'A002 LOGIN user pass\r\n')
    data = bytes(cmd)
    assert b'A002 LOGIN' in data
    
    rsp = IMAPResponse(b'A002 OK LOGIN completed\r\n')
    assert bytes(rsp) == b'A002 OK LOGIN completed\r\n'
