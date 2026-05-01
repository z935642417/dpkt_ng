# -*- coding: utf-8 -*-
"""SMTP protocol parsing (RFC 5321)."""
from __future__ import absolute_import, print_function


class SMTPCommand(object):
    """SMTP command: verb + optional args, CRLF terminated."""
    def __init__(self, raw=b''):
        self.verb = b''; self.args = b''
        if raw: self._parse(raw)

    def _parse(self, raw):
        line = raw.rstrip(b'\r\n')
        space = line.find(b' ')
        if space > 0:
            self.verb = line[:space].upper()
            self.args = line[space+1:].strip()
        else:
            self.verb = line.upper()
            self.args = b''

    def __repr__(self):
        return 'SMTPCommand(verb=%s, args=%s)' % (self.verb, self.args[:50])

    def __bytes__(self):
        if self.args: return self.verb + b' ' + self.args + b'\r\n'
        return self.verb + b'\r\n'


class SMTPResponse(object):
    """SMTP response: 3-digit code + text, single or multi-line.

    Multi-line format:
      250-SIZE 35882577\r\n
      250-PIPELINING\r\n
      250 HELP\r\n
    Last line has code + space (not dash).
    """
    def __init__(self, raw=b''):
        self.code = 0; self.lines = []  # text lines (without code prefix)
        self.is_multiline = False
        if raw: self._parse(raw)

    def _parse(self, raw):
        raw = raw.replace(b'\r\n', b'\n')
        if raw.endswith(b'\n'): raw = raw[:-1]
        all_lines = raw.split(b'\n')
        if not all_lines: return

        # First line gives code
        first = all_lines[0]
        if len(first) >= 3 and first[:3].isdigit():
            self.code = int(first[:3])
            self.is_multiline = (len(first) > 3 and first[3:4] == b'-')
            # Extract text after code+sep
            text = first[4:] if len(first) >= 4 else b''
        else:
            return

        self.lines = [text]
        for line in all_lines[1:]:
            if len(line) >= 4 and line[:4] == (str(self.code).encode() + b' '):
                self.lines.append(line[4:])
            elif len(line) >= 4 and line[:4] == (str(self.code).encode() + b'-'):
                self.lines.append(line[4:])
            else:
                self.lines.append(line)

    def get_extensions(self):
        """Extract ESMTP extension keywords from EHLO response."""
        exts = []
        for line in self.lines:
            part = line.split(b' ', 1)[0].strip() if line else b''
            if part and part.isalpha():
                exts.append(part.upper())
        return exts

    @property
    def text(self):
        return b'\n'.join(self.lines) if self.lines else b''

    def __repr__(self):
        m = 'MULTI ' if self.is_multiline else ''
        return 'SMTPResponse(%scode=%d, text=%s)' % (m, self.code, self.text[:50])

    def __bytes__(self):
        if not self.lines: return b''
        result = []
        code = str(self.code).encode()
        last = len(self.lines) - 1
        for i, line in enumerate(self.lines):
            sep = b' ' if i == last else b'-'
            result.append(code + sep + line + b'\r\n')
        return b''.join(result)


class SMTP(object):
    """SMTP message parser with incremental feed."""
    def __init__(self):
        self.commands = []; self.responses = []
        self._buffer = b''; self._pending_lines = []

    def feed(self, data):
        self._buffer += data
        self._process()

    def _process(self):
        while b'\r\n' in self._buffer:
            idx = self._buffer.index(b'\r\n') + 2
            line = self._buffer[:idx]
            stripped = line.rstrip(b'\r\n')
            self._buffer = self._buffer[idx:]

            if not stripped: continue

            # Response: starts with 3 digits
            if len(stripped) >= 3 and stripped[:3].isdigit():
                self._pending_lines.append(line)
                is_last = (len(stripped) > 3 and stripped[3:4] == b' ') or \
                          len(stripped) == 3
                if is_last:
                    raw = b''.join(self._pending_lines)
                    self.responses.append(SMTPResponse(raw))
                    self._pending_lines = []
            else:
                self.commands.append(SMTPCommand(line))


# ---- Tests ----
def test_smtp_command():
    cmd = SMTPCommand(b'MAIL FROM:<a@b.com>\r\n')
    assert cmd.verb == b'MAIL'
    assert b'a@b.com' in cmd.args
    assert bytes(cmd) == b'MAIL FROM:<a@b.com>\r\n'

def test_smtp_response_single():
    rsp = SMTPResponse(b'250 OK\r\n')
    assert rsp.code == 250
    assert rsp.lines == [b'OK']
    assert not rsp.is_multiline

def test_smtp_response_multi():
    rsp = SMTPResponse(b'250-SIZE 35882577\r\n250-PIPELINING\r\n250 HELP\r\n')
    assert rsp.code == 250
    assert rsp.is_multiline
    assert len(rsp.lines) == 3
    assert rsp.lines[2] == b'HELP'

def test_smtp_extensions():
    rsp = SMTPResponse(b'250-SIZE\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 AUTH LOGIN\r\n')
    exts = rsp.get_extensions()
    assert b'SIZE' in exts
    assert b'STARTTLS' in exts
    assert b'AUTH' in exts

def test_smtp_feed():
    p = SMTP()
    p.feed(b'EHLO client\r\n250-SIZE\r\n250 HELP\r\nMAIL FROM:<>\r\n250 OK\r\n')
    assert len(p.commands) == 2
    assert p.commands[0].verb == b'EHLO'
    assert p.commands[1].verb == b'MAIL'
    assert len(p.responses) == 2
    assert p.responses[0].code == 250 and p.responses[0].is_multiline

def test_smtp_roundtrip():
    rsp = SMTPResponse(b'220 smtp.example.com ESMTP\r\n')
    data = bytes(rsp)
    assert data == b'220 smtp.example.com ESMTP\r\n'

    cmd = SMTPCommand(b'QUIT\r\n')
    assert SMTPCommand(bytes(cmd)).verb == b'QUIT'
