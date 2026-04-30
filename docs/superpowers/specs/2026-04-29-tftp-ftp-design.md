# TFTP Enhancement & FTP Protocol Support — Design Specification

**Date:** 2026-04-29  
**Status:** Draft  
**Scope:** dpkt_ng — TFTP options (RFC 2347) + FTP protocol parsing

---

## 1. Overview

Two independent protocol enhancements sharing core design principles: transport-layer independence, pure byte-buffer input, dpkt coding conventions, and inline pytest testing.

### 1.1 TFTP Enhancement

Enhance the existing `dpkt/tftp.py` to support RFC 2347 options (blksize, tsize, timeout, multicast, windowsize), OACK (opcode 6), malformed-packet tolerance, and improved serialization/debugging.

### 1.2 FTP Support

Add new `dpkt/ftp.py` with control-channel parsing (commands, replies, multi-line replies) and data-channel parsing (file content extraction in ASCII/binary mode). No session-layer state tracking.

### 1.3 Design Principles

- **Transport-independent**: Parsers accept byte buffers only; no dependency on UDP, TCP, or stream reassembly.
- **dpkt conventions**: Inline pytest tests, `from . import dpkt`, `__future__` imports, module-level constants.
- **Self-contained**: TFTP and FTP are independent; can coexist without conflict.

---

## 2. TFTP Enhancement (`dpkt/tftp.py`)

### 2.1 Constants (additions)

```python
OP_OACK = 6  # Option acknowledgment

# Error codes (existing, unchanged)

# RFC 2347 option names
TFTP_OPT_BLKSIZE = 'blksize'
TFTP_OPT_TSIZE = 'tsize'
TFTP_OPT_TIMEOUT = 'timeout'
TFTP_OPT_MULTICAST = 'multicast'
TFTP_OPT_WINDOWSIZE = 'windowsize'
```

### 2.2 TFTP Class (enhancements)

**Existing attributes preserved:**
```python
__byte_order__ = '>'
__hdr__ = (('opcode', 'H', 1),)
```

**New attributes:**
```python
options: dict = {}         # {name_bytes: value_bytes}
strict: bool = False       # Tolerance mode
```

**Enhanced `unpack()`:**

```
dispatch by opcode:

OP_RRQ / OP_WRQ:
  1. Split self.data on b'\x00' into segments
  2. segments[0] → filename, segments[1] → mode (lenient: empty string if missing)
  3. Remaining segments parsed as option key-value pairs:
     For i in range(2, len(segments)-1, 2):
         if strict and i+1 >= len(segments):
             raise UnpackError('missing option value')
         key = segments[i]
         val = segments[i+1] if i+1 < len(segments) else b''
         if key: options[key] = val  # skip empty keys

OP_DATA:
  1. self.block = struct.unpack('>H', self.data[:2])[0]
  2. self.data = self.data[2:]  # payload

OP_ACK:
  1. self.block = struct.unpack('>H', self.data[:2])[0]
  2. self.data = b''

OP_ERR:
  1. self.errcode = struct.unpack('>H', self.data[:2])[0]
  2. Split remaining on b'\x00': self.errmsg = parts[0] if parts else b''
  3. self.data = b''

OP_OACK (new):
  1. Split self.data on b'\x00'
  2. Parse key-value pairs same as RRQ/WRQ options
```

**Enhanced `__bytes__()`:**

```
RRQ/WRQ/OACK:
  parts = [filename, mode] if has filename/mode else []
  for key, val in options.items():
      parts.append(key)
      parts.append(val)
  serialized = b'\x00'.join(parts) + b'\x00'
  return self.pack_hdr() + serialized

DATA/ACK/ERR: (unchanged logic)
```

**New `__repr__()`:**

```python
def __repr__(self):
    op_names = {1: 'RRQ', 2: 'WRQ', 3: 'DATA', 4: 'ACK', 5: 'ERR', 6: 'OACK'}
    parts = [op_names.get(self.opcode, 'UNKNOWN')]
    if hasattr(self, 'filename'): parts.append('file=' + str(self.filename))
    if self.options: parts.append('opts=' + str(self.options))
    return 'TFTP(' + ', '.join(parts) + ')'
```

**New `get_option()`:**

```python
def get_option(self, name, default=None):
    return self.options.get(name, default)
```

### 2.3 Error Tolerance

| Scenario | `strict=False` | `strict=True` |
|----------|---------------|---------------|
| Missing final null | Truncate last segment | `UnpackError` |
| Odd option count | Accept last key without value | `UnpackError` |
| Empty option key | Skip | `UnpackError` |
| Data too short for block | `self.block = 0` | `NeedData` |

---

## 3. FTP Protocol (`dpkt/ftp.py`)

### 3.1 File Organization

```
dpkt/ftp.py  (~350 lines)
├── FTPCommand          # Control channel command
├── FTPReply            # Control channel reply
├── FTPControlParser    # Control channel stream parser
├── FTPDataParser       # Data channel parser
└── FTPError(Exception) # FTP protocol errors
```

### 3.2 FTPCommand

```python
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
            self.args = line[space+1:]
        else:
            self.verb = line.upper()
            self.args = b''

    def __repr__(self):
        return "FTPCommand(verb=%s, args=%s)" % (self.verb, self.args)

    def __bytes__(self):
        if self.args:
            return self.verb + b' ' + self.args + b'\r\n'
        return self.verb + b'\r\n'
```

### 3.3 FTPReply

```python
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
        # First line determines code and multi-line status
        first = self.lines[0]
        self.code = int(first[:3])
        self.is_multi_line = (len(first) > 3 and first[3:4] == b'-')
        # Extract text: strip code + separator, join lines with \n
        texts = []
        for line in self.lines:
            if line[:3] == str(self.code).encode():
                texts.append(line[4:])  # after "NNN-" or "NNN "
            else:
                texts.append(line)
        self.text = b'\n'.join(texts)

    # Convenience predicates
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
            if i == len(self.lines) - 1:
                result.append(str(self.code).encode() + b' ' + line[4:])
            else:
                result.append(str(self.code).encode() + b'-' + line[4:])
        return b''.join(result)
```

### 3.4 FTPControlParser

```python
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
            line_end = self._buffer.index(b'\r\n') + 2
            line = self._buffer[:line_end]
            self._buffer = self._buffer[line_end:]
            self._dispatch_line(line)

    def _dispatch_line(self, line):
        stripped = line.rstrip(b'\r\n')
        if not stripped:
            return  # empty line

        # Reply lines start with 3 digits
        if len(stripped) >= 3 and stripped[:3].isdigit():
            self._pending_reply_lines.append(line)
            # Check if this is the last line of a multi-line reply
            if len(stripped) > 3 and stripped[3:4] == b' ':
                # Last line: commit reply
                reply = FTPReply(self._pending_reply_lines)
                self.replies.append(reply)
                self._pending_reply_lines = []
            elif len(stripped) == 3 or (len(stripped) > 3 and stripped[3:4] != b'-'):
                # Single-line reply (no '-' after code, or exact 3-char code)
                if len(stripped) > 3 and stripped[3:4] != b'-':
                    # Single line with code + space
                    reply = FTPReply([line])
                    self.replies.append(reply)
                    self._pending_reply_lines = []
                else:
                    # Exact 3-char reply code (unusual but valid)
                    reply = FTPReply([line])
                    self.replies.append(reply)
                    self._pending_reply_lines = []
            # else: continuation line ("NNN-"), accumulate
        else:
            # Command line
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
```

### 3.5 FTPDataParser

```python
class FTPDataParser(object):
    """Parse FTP data channel byte stream."""
    def __init__(self, data, mode='binary'):
        self.data = data
        self.mode = mode
        self.file_data = b''
        self._parse()

    def _parse(self):
        if self.mode == 'ascii':
            # Convert CRLF → LF
            self.file_data = self.data.replace(b'\r\n', b'\n')
            # Strip trailing newline if present
            if self.file_data.endswith(b'\n'):
                self.file_data = self.file_data[:-1]
        else:
            self.file_data = self.data

    def __repr__(self):
        return "FTPDataParser(mode=%s, size=%d)" % (self.mode, len(self.file_data))

    def __bytes__(self):
        return self.data
```

### 3.6 FTPError

```python
class FTPError(Exception):
    """FTP protocol error."""
    pass
```

---

## 4. Integration Examples

### 4.1 FTP with TCP stream reassembly

```python
import dpkt

reasm = dpkt.stream.StreamReassembler()
reasm.feed_pcap(dpkt.pcap.Reader(open('ftp.pcap', 'rb')))

for conn_id in reasm.connections:
    conn = reasm[conn_id]
    if conn.dst_port == 21:
        # Control channel
        parser = dpkt.ftp.FTPControlParser()
        parser.feed(conn.c2s.get_data())  # client commands
        parser.feed(conn.s2c.get_data())  # server replies
        for reply in parser.replies:
            print(reply)
    elif conn.dst_port == 20:
        # Active mode data channel
        parser = dpkt.ftp.FTPDataParser(conn.s2c.get_data())
        print(f"File: {len(parser.file_data)} bytes")
```

### 4.2 FTP without stream reassembly (direct buffer)

```python
import dpkt

# Parse a pre-assembled control channel log
with open('ftp_control.txt', 'rb') as f:
    data = f.read()
parser = dpkt.ftp.FTPControlParser()
parser.feed(data)

# Extract PASS command arguments
for cmd in parser.commands:
    if cmd.verb == b'PASS':
        print(f"Password: {cmd.args}")
```

### 4.3 TFTP with options

```python
import dpkt

# Parse TFTP RRQ with options
buf = b'\x00\x01file.txt\x00octet\x00blksize\x001024\x00tsize\x000\x00'
tftp = dpkt.tftp.TFTP(buf)
print(tftp.filename)       # b'file.txt'
print(tftp.get_option(b'blksize'))  # b'1024'

# Construct and serialize
tftp2 = dpkt.tftp.TFTP(
    opcode=dpkt.tftp.OP_WRQ,
    filename=b'upload.bin',
    mode=b'octet',
    options={b'blksize': b'4096'}
)
wire = bytes(tftp2)
```

---

## 5. Testing Strategy

### 5.1 TFTP Tests (~8 tests)

| Test | Coverage |
|------|----------|
| `test_op_rrq` | Existing — preserved as-is |
| `test_op_data` | Existing — preserved |
| `test_op_err` | Existing — preserved |
| `test_op_wrq` | New — WRQ with options |
| `test_op_oack` | New — OACK parsing |
| `test_op_options` | New — RRQ with blksize+tsize |
| `test_lenient_missing_null` | New — Tolerance mode |
| `test_strict_missing_null` | New — Strict mode exception |
| `test_roundtrip_options` | New — Construct→bytes→parse |

### 5.2 FTP Tests (~10 tests)

| Test | Coverage |
|------|----------|
| `test_ftp_command` | FTPCommand parsing (USER, PASS, RETR) |
| `test_ftp_reply_single` | Single-line reply |
| `test_ftp_reply_multi` | Multi-line reply (220-Welcome) |
| `test_ftp_control_parser` | FTPControlParser feed incremental |
| `test_ftp_control_parser_mixed` | Commands + replies interleaved |
| `test_ftp_data_binary` | Binary data extraction |
| `test_ftp_data_ascii` | ASCII CRLF→LF conversion |
| `test_ftp_command_bytes` | FTPCommand roundtrip |
| `test_ftp_reply_bytes` | FTPReply roundtrip |
| `test_ftp_reply_predicates` | Code range predicates |

---

## 6. Non-Goals

- FTP session layer (PASV/PORT state tracking)
- FTP over TLS (FTPS)
- TFTP option negotiation state machine
- Automatic UDP port dispatch for TFTP (port 69)
- Active FTP data connection management

---

## 7. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Break existing TFTP tests | Preserve all existing tests unchanged; add new tests only |
| FTP multi-line reply edge cases | Handle "NNN " / "NNN-" / bare "NNN" all correctly |
| Large FTP data channels | FTPDataParser operates on complete buffer; caller controls memory |
| Binary data misidentified as commands | FTPControlParser only operates on explicitly fed control-channel data |

---

*End of Design Specification*
