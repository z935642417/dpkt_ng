# -*- coding: utf-8 -*-
"""POP3 protocol parsing (RFC 1939)."""
from __future__ import absolute_import, print_function


class POP3Command(object):
    """POP3 command: verb + optional args, CRLF terminated."""
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
        return 'POP3Command(verb=%s, args=%s)' % (self.verb, self.args)

    def __bytes__(self):
        if self.args:
            return self.verb + b' ' + self.args + b'\r\n'
        return self.verb + b'\r\n'


class POP3Response(object):
    """POP3 response: single-line (+OK text) or multi-line (+OK\nlines\n.\n)."""
    def __init__(self, raw=b''):
        self.ok = False
        self.text = b''       # status line text (after +OK/-ERR)
        self.lines = []       # multi-line data lines
        self.is_multiline = False
        if raw: self._parse(raw)

    def _parse(self, raw):
        raw = raw.replace(b'\r\n', b'\n')
        if raw.endswith(b'\n'):
            raw = raw[:-1]

        # Check status
        if raw.startswith(b'+OK'):
            self.ok = True
        elif raw.startswith(b'-ERR'):
            self.ok = False
        else:
            self.ok = False
            self.text = raw
            return

        # Split into lines
        all_lines = raw.split(b'\n')
        # Status line
        self.text = all_lines[0][4:]  # strip "+OK " or "-ERR "
        if self.text.startswith(b' '): self.text = self.text[1:]

        # Multi-line check: lines after status, terminated by "."
        if len(all_lines) > 1:
            self.is_multiline = True
            self.lines = []
            for line in all_lines[1:]:
                if line == b'.': break  # terminator
                if line.startswith(b'..'): line = line[1:]  # byte-stuffed
                self.lines.append(line)

    def __repr__(self):
        status = '+OK' if self.ok else '-ERR'
        if self.is_multiline:
            return 'POP3Response(%s, lines=%d)' % (status, len(self.lines))
        return 'POP3Response(%s, text=%s)' % (status, self.text[:50])

    def __bytes__(self):
        return b'\r\n'.join(self._to_lines()) + b'\r\n'

    def _to_lines(self):
        status = b'+OK' if self.ok else b'-ERR'
        lines = [status + b' ' + self.text] if self.text else [status]
        if self.is_multiline:
            for line in self.lines:
                if line.startswith(b'.'): line = b'.' + line
                lines.append(line)
            lines.append(b'.')
        return lines


class POP3(object):
    """POP3 message parser with incremental feed."""
    def __init__(self):
        self.commands = []; self.responses = []
        self._buffer = b''
        self._in_multiline = False
        self._pending = None   # pending response line (might be single or start of multi)

    def feed(self, data):
        """Feed raw bytes from TCP stream."""
        self._buffer += data
        self._process()

    def _process(self):
        while b'\r\n' in self._buffer:
            idx = self._buffer.index(b'\r\n') + 2
            line = self._buffer[:idx]
            stripped = line.rstrip(b'\r\n')

            if self._in_multiline:
                self._ml_buffer.append(stripped)
                if stripped == b'.':  # multiline terminator
                    raw = b'\r\n'.join(self._ml_buffer) + b'\r\n'
                    self.responses.append(POP3Response(
                        self._ml_start + b' ' + raw))
                    self._in_multiline = False
                self._buffer = self._buffer[idx:]
                continue

            if stripped.startswith(b'+OK') or stripped.startswith(b'-ERR'):
                if b' ' not in stripped:
                    # No space: definitely single-line, flush any pending first
                    if self._pending:
                        self.responses.append(POP3Response(self._pending))
                        self._pending = None
                    self.responses.append(POP3Response(line))
                else:
                    # Has space: could be single-line or start of multi-line.
                    # Flush previous pending as single-line, then hold this one.
                    if self._pending:
                        self.responses.append(POP3Response(self._pending))
                    if stripped.startswith(b'-ERR'):
                        # -ERR is always single-line (RFC 1939)
                        self.responses.append(POP3Response(line))
                        self._pending = None
                    else:
                        self._pending = line
                self._buffer = self._buffer[idx:]
                continue

            # Line does not start with +OK/-ERR; it's either a data line
            # belonging to a pending multi-line response, or a command.
            if self._pending:
                # Start collecting as a multi-line response
                self._in_multiline = True
                self._ml_start = self._pending.rstrip(b'\r\n').split(b' ', 1)[0]
                self._ml_buffer = [self._pending.rstrip(b'\r\n')]
                self._pending = None
                # Fall through to process current line as first data line
                self._ml_buffer.append(stripped)
                if stripped == b'.':
                    raw = b'\r\n'.join(self._ml_buffer) + b'\r\n'
                    self.responses.append(POP3Response(
                        self._ml_start + b' ' + raw))
                    self._in_multiline = False
                self._buffer = self._buffer[idx:]
                continue

            self.commands.append(POP3Command(line))
            self._buffer = self._buffer[idx:]

        # Flush pending single-line response if no more data to determine
        if self._pending and not self._in_multiline:
            self.responses.append(POP3Response(self._pending))
            self._pending = None


# ---- Tests ----
def test_pop3_command():
    cmd = POP3Command(b'USER alice\r\n')
    assert cmd.verb == b'USER'
    assert cmd.args == b'alice'
    assert bytes(cmd) == b'USER alice\r\n'

def test_pop3_response_ok():
    rsp = POP3Response(b'+OK welcome\r\n')
    assert rsp.ok
    assert rsp.text == b'welcome'
    assert not rsp.is_multiline

def test_pop3_response_err():
    rsp = POP3Response(b'-ERR unknown command\r\n')
    assert not rsp.ok
    assert b'unknown' in rsp.text

def test_pop3_multiline_list():
    rsp = POP3Response(b'+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n')
    assert rsp.ok and rsp.is_multiline
    assert len(rsp.lines) == 2
    assert rsp.lines[0] == b'1 120'
    assert rsp.lines[1] == b'2 200'

def test_pop3_multiline_retr():
    rsp = POP3Response(b'+OK\r\nFrom: alice\r\nSubject: hi\r\nline1\r\n.\r\n')
    assert rsp.is_multiline
    assert b'From: alice' in rsp.lines
    assert len(rsp.lines) == 3

def test_pop3_feed():
    p = POP3()
    p.feed(b'USER alice\r\n+OK user ok\r\n')
    assert len(p.commands) == 1
    assert len(p.responses) == 1
    assert p.responses[0].ok

def test_pop3_roundtrip():
    cmd = POP3Command(b'RETR 1\r\n')
    assert POP3Command(bytes(cmd)).verb == b'RETR'
    rsp = POP3Response(b'+OK 1 message\r\nline1\r\nline2\r\n.\r\n')
    data = bytes(rsp)
    assert b'line1' in data
    assert data.endswith(b'.\r\n')
