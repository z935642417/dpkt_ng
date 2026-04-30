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


class FTPControlParser(object):
    """Parse FTP control channel byte stream into commands and replies."""
    def __init__(self):
        self.commands = []
        self.replies = []
        self._buffer = b''
        self._pending_reply_lines = []

    def feed(self, data):
        """Feed raw bytes (from reassembled TCP stream)."""
        self._buffer += data
        self._process_buffer()

    def _process_buffer(self):
        while b'\r\n' in self._buffer:
            idx = self._buffer.index(b'\r\n') + 2
            line = self._buffer[:idx]
            self._buffer = self._buffer[idx:]
            self._dispatch_line(line)

    def _dispatch_line(self, line):
        stripped = line.rstrip(b'\r\n')
        if not stripped:
            return
        if len(stripped) >= 3 and stripped[:3].isdigit():
            self._pending_reply_lines.append(line)
            if len(stripped) > 3 and stripped[3:4] == b' ':
                reply = FTPReply(list(self._pending_reply_lines))
                self.replies.append(reply)
                self._pending_reply_lines = []
            elif len(stripped) == 3 or (len(stripped) > 3 and stripped[3:4] != b'-'):
                reply = FTPReply(self._pending_reply_lines)
                self.replies.append(reply)
                self._pending_reply_lines = []
        else:
            cmd = FTPCommand(line)
            self.commands.append(cmd)

    def get_commands(self):
        return self.commands

    def get_replies(self):
        return self.replies

    def get_reply_by_code(self, code):
        for r in self.replies:
            if r.code == code:
                return r
        return None


class FTPDataParser(object):
    """Parse FTP data channel byte stream."""
    def __init__(self, data, mode='binary'):
        self.data = data
        self.mode = mode
        self.file_data = b''
        self._parse()

    def _parse(self):
        if self.mode == 'ascii':
            self.file_data = self.data.replace(b'\r\n', b'\n')
            if self.file_data.endswith(b'\n'):
                self.file_data = self.file_data[:-1]
        else:
            self.file_data = self.data

    def __repr__(self):
        return "FTPDataParser(mode=%s, size=%d)" % (self.mode, len(self.file_data))

    def __bytes__(self):
        return self.data


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

def test_ftp_control_parser_commands():
    """Parse multiple commands from stream."""
    parser = FTPControlParser()
    parser.feed(b'USER alice\r\nPASS secret\r\n')
    cmds = parser.get_commands()
    assert len(cmds) == 2
    assert cmds[0].verb == b'USER'
    assert cmds[1].verb == b'PASS'

def test_ftp_control_parser_replies():
    """Parse multi-line reply from stream."""
    parser = FTPControlParser()
    parser.feed(b'220-Welcome\r\n220-Please\r\n220 End\r\n')
    replies = parser.get_replies()
    assert len(replies) == 1
    assert replies[0].code == 220
    assert replies[0].is_multi_line

def test_ftp_control_parser_mixed():
    """Parse interleaved commands and replies."""
    parser = FTPControlParser()
    parser.feed(b'USER alice\r\n331 Password\r\nPASS secret\r\n230 Logged in\r\n')
    assert len(parser.get_commands()) == 2
    assert len(parser.get_replies()) == 2
    assert parser.get_reply_by_code(230) is not None
    assert parser.get_reply_by_code(999) is None

def test_ftp_control_parser_incremental():
    """Feed data incrementally (simulating TCP segments)."""
    parser = FTPControlParser()
    parser.feed(b'USER ali')
    assert len(parser.get_commands()) == 0
    parser.feed(b'ce\r\nPASS secret\r\n')
    assert len(parser.get_commands()) == 2

def test_ftp_data_binary():
    """Binary data pass-through."""
    data = b'\x89PNG\r\n\x1a\n\x00'
    parser = FTPDataParser(data, mode='binary')
    assert parser.file_data == data

def test_ftp_data_ascii():
    """ASCII mode: CRLF→LF conversion."""
    parser = FTPDataParser(b'line1\r\nline2\r\n', mode='ascii')
    assert parser.file_data == b'line1\nline2'

def test_ftp_data_repr():
    parser = FTPDataParser(b'hello', mode='binary')
    assert 'binary' in repr(parser)
    assert 'size=5' in repr(parser)


def test_ftp_end_to_end():
    """Full FTP session: login → data transfer."""
    parser = FTPControlParser()
    session = (
        b'220 FTP server ready\r\n'
        b'USER alice\r\n'
        b'331 Password required\r\n'
        b'PASS secret\r\n'
        b'230 Logged in\r\n'
        b'PASV\r\n'
        b'227 Entering Passive (10,0,0,1,19,137)\r\n'
        b'RETR readme.txt\r\n'
        b'150 Opening data\r\n'
        b'226 Transfer complete\r\n'
        b'QUIT\r\n'
        b'221 Goodbye\r\n'
    )
    parser.feed(session)
    assert len(parser.get_commands()) == 5
    assert len(parser.get_replies()) == 7
    assert parser.get_reply_by_code(230) is not None
    assert parser.get_reply_by_code(227) is not None

    # Verify data channel works independently
    data_parser = FTPDataParser(b'Hello World', mode='binary')
    assert data_parser.file_data == b'Hello World'
