# -*- coding: utf-8 -*-
"""File Transfer Protocol."""
from __future__ import print_function
from __future__ import absolute_import


class FTPError(Exception):
    """FTP protocol error."""
    pass


class FTPCommand(object):
    """FTP control channel command."""
    def __init__(self, raw=b''):
        self.raw = raw
        self.verb = b''
        self.args = b''
        self._parse()

    def _parse(self):
        line = self.raw.rstrip(b'\r\n')
        space = line.find(b' ')
        if space > 0:
            self.verb = line[:space].upper()
            self.args = line[space + 1:]
        else:
            self.verb = line.upper()
            self.args = b''

    def __repr__(self):
        return "FTPCommand(verb=%s, args=%s)" % (self.verb, self.args)

    def __bytes__(self):
        if self.args:
            return self.verb + b' ' + self.args + b'\r\n'
        return self.verb + b'\r\n'


class FTPReply(object):
    """FTP control channel reply (single or multi-line)."""
    def __init__(self, lines=None):
        self.lines = lines or []
        self.code = 0
        self.text = b''
        self.is_multi_line = False
        if self.lines:
            self._parse()

    def _parse(self):
        first = self.lines[0].rstrip(b'\r\n')
        self.code = int(first[:3])
        self.is_multi_line = (len(first) > 3 and first[3:4] == b'-')
        texts = []
        for line in self.lines:
            stripped = line.rstrip(b'\r\n')
            if len(stripped) >= 4 and stripped[:3] == str(self.code).encode():
                texts.append(stripped[4:])
            else:
                texts.append(stripped)
        self.text = b'\n'.join(texts)

    def is_positive_preliminary(self): return 100 <= self.code < 200
    def is_positive_completion(self): return 200 <= self.code < 300
    def is_positive_intermediate(self): return 300 <= self.code < 400
    def is_transient_negative(self): return 400 <= self.code < 500
    def is_permanent_negative(self): return 500 <= self.code < 600

    def __repr__(self):
        return "FTPReply(code=%d, text=%s)" % (self.code, self.text[:50])

    def __bytes__(self):
        if not self.lines:
            return b''
        result = []
        for i, line in enumerate(self.lines):
            stripped = line.rstrip(b'\r\n')
            sep = b' ' if i == len(self.lines) - 1 else b'-'
            data_part = stripped[4:] if len(stripped) >= 4 else b''
            result.append(str(self.code).encode() + sep + data_part + b'\r\n')
        return b''.join(result)


def test_ftp_command():
    """Parse FTP USER command."""
    cmd = FTPCommand(b'USER anonymous\r\n')
    assert cmd.verb == b'USER'
    assert cmd.args == b'anonymous'

def test_ftp_command_no_args():
    """Parse command without arguments."""
    cmd = FTPCommand(b'QUIT\r\n')
    assert cmd.verb == b'QUIT'
    assert cmd.args == b''

def test_ftp_reply_single():
    """Parse single-line reply."""
    reply = FTPReply([b'220 Welcome\r\n'])
    assert reply.code == 220
    assert reply.is_multi_line == False
    assert b'Welcome' in reply.text

def test_ftp_reply_multi():
    """Parse multi-line reply."""
    lines = [b'220-Welcome\r\n', b'220-Please read\r\n', b'220 End\r\n']
    reply = FTPReply(lines)
    assert reply.code == 220
    assert reply.is_multi_line == True
    assert reply.text == b'Welcome\nPlease read\nEnd'

def test_ftp_command_bytes():
    """FTPCommand roundtrip."""
    cmd = FTPCommand(b'RETR file.txt\r\n')
    assert bytes(cmd) == b'RETR file.txt\r\n'

def test_ftp_reply_bytes():
    """FTPReply roundtrip."""
    lines = [b'220-Welcome\r\n', b'220 End\r\n']
    reply = FTPReply(lines)
    data = bytes(reply)
    assert b'220-Welcome\r\n' in data
    assert b'220 End\r\n' in data

def test_ftp_reply_predicates():
    """Reply code range predicates."""
    r = FTPReply([b'200 OK\r\n'])
    assert r.is_positive_completion()
    assert not r.is_positive_intermediate()
    r2 = FTPReply([b'500 Error\r\n'])
    assert r2.is_permanent_negative()
