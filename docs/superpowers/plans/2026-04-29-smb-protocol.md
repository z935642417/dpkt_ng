# SMB Protocol Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full SMB1 and SMB2 protocol parsing (headers, 19+16 commands, ANDX chains, file content extraction) and NBSS transport wrapper to dpkt_ng.

**Architecture:** Three new/enhanced modules — `dpkt/smb2.py` (SMB2 64-byte header + 19 command parsers), `dpkt/smb.py` (enhanced SMB1 + ANDX chain + 16 commands), `dpkt/nbss.py` (NetBIOS Session Service 4-byte wrapper). Follows dpkt patterns: `__hdr__`/`__bit_fields__` for headers, `_cmdsw` dict for command dispatch, `_mod_init()` for auto-loading, inline pytest tests.

**Tech Stack:** Python 3, dpkt metaclass (`_MetaPacket`), `struct` for binary parsing, pytest (inline `def test_*` in module files)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `dpkt/smb2.py` | **Create** | SMB2 class, 19 command classes, constants, `_mod_init()`, inline tests |
| `dpkt/smb.py` | **Modify** | Add `SMB1Command` base, 16 command classes, ANDX chain parsing, `_mod_init()`, preserve existing header+test |
| `dpkt/nbss.py` | **Create** | NBSS class, inline tests |
| `dpkt/__init__.py` | **Modify** | Add `from . import nbss` and `from . import smb2` imports |

---

## Phase 1: SMB2 Core (Tasks 1–9)

### Task 1: Create smb2.py — SMB2 Header Class

**Files:**
- Create: `dpkt/smb2.py`

- [ ] **Step 1: Write failing test for SMB2 header parsing**

```python
# In dpkt/smb2.py (end of file)
def test_smb2_header():
    """Verify SMB2 64-byte header unpack."""
    from binascii import unhexlify
    # 64-byte minimal SMB2 NEGOTIATE request
    buf = unhexlify(
        'fe534d4240000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
    )
    smb2 = SMB2(buf)
    assert smb2.proto == b'\xfeSMB'
    assert smb2.hdr_len == 64
    assert smb2.cmd == 0
    assert len(bytes(smb2)) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest dpkt/smb2.py::test_smb2_header -v`  
Expected: FAIL with `NameError: name 'SMB2' is not defined`

- [ ] **Step 3: Write SMB2 class with __hdr__**

```python
# dpkt/smb2.py
# -*- coding: utf-8 -*-
"""Server Message Block version 2."""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt


class SMB2(dpkt.Packet):
    """SMB2 Protocol Packet.

    Attributes:
        __hdr__: SMB2 64-byte fixed header
    """
    __byte_order__ = '<'
    __hdr__ = [
        ('proto', '4s', b'\xfeSMB'),
        ('hdr_len', 'H', 64),
        ('credit_charge', 'H', 0),
        ('_chan_seq', 'I', 0),
        ('cmd', 'H', 0),
        ('credit_req', 'H', 0),
        ('_flags', 'I', 0),
        ('next_cmd', 'I', 0),
        ('mid', 'Q', 0),
        ('pid', 'I', 0),
        ('tid', 'I', 0),
        ('sid', 'Q', 0),
        ('sig', '16s', b'\x00' * 16),
    ]
    __bit_fields__ = {
        '_flags': (
            ('_rsv1', 4),
            ('priority', 3),
            ('_rsv2', 2),
            ('dfs', 1),
            ('_rsv3', 2),
            ('replay', 1),
            ('_rsv4', 2),
            ('signed', 1),
            ('_rsv5', 2),
            ('related', 1),
            ('async', 1),
            ('response', 1),
        ),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest dpkt/smb2.py::test_smb2_header -v`  
Expected: PASS

- [ ] **Step 5: Add SMB2_FLAGS_* constants above the class**

```python
# SMB2 Flags
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
SMB2_FLAGS_ASYNC_COMMAND = 0x00000002
SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
SMB2_FLAGS_SIGNED = 0x00000008
SMB2_FLAGS_PRIORITY_MASK = 0x00000070
SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
SMB2_FLAGS_REPLAY_OPERATION = 0x20000000

# SMB2 Command codes
SMB2_CMD_NEGOTIATE = 0x0000
SMB2_CMD_SESSION_SETUP = 0x0001
SMB2_CMD_LOGOFF = 0x0002
SMB2_CMD_TREE_CONNECT = 0x0003
SMB2_CMD_TREE_DISCONNECT = 0x0004
SMB2_CMD_CREATE = 0x0005
SMB2_CMD_CLOSE = 0x0006
SMB2_CMD_FLUSH = 0x0007
SMB2_CMD_READ = 0x0008
SMB2_CMD_WRITE = 0x0009
SMB2_CMD_LOCK = 0x000A
SMB2_CMD_IOCTL = 0x000B
SMB2_CMD_CANCEL = 0x000C
SMB2_CMD_ECHO = 0x000D
SMB2_CMD_QUERY_DIRECTORY = 0x000E
SMB2_CMD_CHANGE_NOTIFY = 0x000F
SMB2_CMD_QUERY_INFO = 0x0010
SMB2_CMD_SET_INFO = 0x0011
SMB2_CMD_OPLOCK_BREAK = 0x0012
```

- [ ] **Step 6: Add header roundtrip test and flags test**

```python
def test_smb2_flags():
    """Test SMB2 flag bit fields."""
    smb2 = SMB2()
    assert smb2.response == 0
    smb2.response = 1
    assert smb2.response == 1
    assert (smb2._flags & 1) == 1
    smb2.signed = 1
    assert smb2.signed == 1

def test_smb2_roundtrip():
    """Test SMB2 pack → unpack → bytes."""
    smb2 = SMB2(cmd=SMB2_CMD_NEGOTIATE, mid=1, pid=0x1234, tid=0x5678, sid=0x9ABC)
    data = bytes(smb2)
    assert len(data) == 64
    parsed = SMB2(data)
    assert parsed.cmd == SMB2_CMD_NEGOTIATE
    assert parsed.mid == 1
    assert parsed.pid == 0x1234
```

- [ ] **Step 7: Run all tests to verify**

Run: `pytest dpkt/smb2.py -v`  
Expected: all tests PASS (3 tests)

- [ ] **Step 8: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 64-byte header class with constants"
```

---

### Task 2: SMB2 Command Dispatch + SMB2Negotiate

**Files:**
- Modify: `dpkt/smb2.py` (add SMB2Negotiate class, dispatch to SMB2.unpack)

- [ ] **Step 1: Write failing test for Negotiate parsing**

```python
def test_smb2_negotiate_request():
    """Test SMB2 NEGOTIATE request parsing."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d4240000000000000000000000000000000'  # SMB2 header
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '240005000000000000000000'                    # Negotiate request body
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_NEGOTIATE
    assert isinstance(smb2.data, SMB2Negotiate)
    assert smb2.data.struct_size == 36
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest dpkt/smb2.py::test_smb2_negotiate_request -v`  
Expected: FAIL (SMB2Negotiate not defined, or raw bytes in data)

- [ ] **Step 3: Add SMB2Negotiate class and dispatch to SMB2.unpack()**

Add after SMB2 class:

```python
class SMB2Negotiate(dpkt.Packet):
    """SMB2 NEGOTIATE Request/Response."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 36),
        ('dialect_count', 'H', 0),
        ('security_mode', 'H', 0),
        ('_rsv', 'H', 0),
        ('capabilities', 'I', 0),
        ('client_guid', '16s', b'\x00' * 16),
        ('_negotiate_flags', 'I', 0),
    ]
```

Modify `SMB2.unpack()` to dispatch:

```python
class SMB2(dpkt.Packet):
    _cmdsw = {}

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            cmd_cls = self._cmdsw[self.cmd]
            self.data = cmd_cls(buf[self.__hdr_len__:])
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf[self.__hdr_len__:]
```

Register command manually (before `_mod_init`):

```python
SMB2._cmdsw[SMB2_CMD_NEGOTIATE] = SMB2Negotiate
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest dpkt/smb2.py::test_smb2_negotiate_request -v`  
Expected: PASS

- [ ] **Step 5: Add Negotiate roundtrip test**

```python
def test_smb2_negotiate_roundtrip():
    """Test SMB2 NEGOTIATE construct → bytes → parse."""
    nego = SMB2Negotiate(dialect_count=2, security_mode=1, capabilities=0x1F)
    smb2 = SMB2(cmd=SMB2_CMD_NEGOTIATE, data=nego)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert isinstance(parsed.data, SMB2Negotiate)
    assert parsed.data.dialect_count == 2
```

- [ ] **Step 6: Run all tests and commit**

Run: `pytest dpkt/smb2.py -v`  
Expected: all PASS

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 command dispatch + Negotiate command"
```

---

### Task 3: SMB2SessionSetup + SMB2TreeConnect + SMB2Create

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Add test data and failing tests for three commands**

```python
def test_smb2_session_setup():
    buf = unhexlify(
        'fe534d4240000000000000000100000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '1900010000000000000000004a00000000000000'  # SessionSetup request body
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_SESSION_SETUP
    assert isinstance(smb2.data, SMB2SessionSetup)
    assert smb2.data.struct_size == 25

def test_smb2_tree_connect():
    buf = unhexlify(
        'fe534d4240000000000000000300000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '09000000080000005c005c004900500043002400'  # TreeConnect request body
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_TREE_CONNECT
    assert isinstance(smb2.data, SMB2TreeConnect)
    assert smb2.data.struct_size == 9

def test_smb2_create():
    buf = unhexlify(
        'fe534d4240000000000000000500000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '3900000000000000000000000000000000000000'  # Create request body
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000066006f00'  # "fo" filename start
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_CREATE
    assert isinstance(smb2.data, SMB2Create)
```

- [ ] **Step 2: Run to confirm failure**

Run: `pytest dpkt/smb2.py::test_smb2_session_setup dpkt/smb2.py::test_smb2_tree_connect dpkt/smb2.py::test_smb2_create -v`  
Expected: FAIL (classes not registered)

- [ ] **Step 3: Implement the three command classes**

```python
class SMB2SessionSetup(dpkt.Packet):
    """SMB2 SESSION_SETUP Request/Response."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 25),
        ('flags', 'B', 0),
        ('security_mode', 'B', 0),
        ('capabilities', 'I', 0),
        ('channel', 'I', 0),
        ('security_blob_offset', 'H', 0),
        ('security_blob_length', 'H', 0),
        ('prev_session_id', 'Q', 0),
    ]


class SMB2TreeConnect(dpkt.Packet):
    """SMB2 TREE_CONNECT Request/Response."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 9),
        ('_flags', 'H', 0),
        ('path_offset', 'H', 0),
        ('path_length', 'H', 0),
    ]
    __bit_fields__ = {
        '_flags': (
            ('_rsv1', 4),
            ('cluster_reconnect', 1),
            ('_rsv2', 3),
            ('redirect_to_owner', 1),
            ('extension_present', 1),
            ('_rsv3', 6),
        ),
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        start = self.path_offset - self.__hdr_len__
        self.path = buf[start:start + self.path_length]
        self.data = b''


class SMB2Create(dpkt.Packet):
    """SMB2 CREATE Request."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 57),
        ('security_flags', 'B', 0),
        ('req_oplock_level', 'B', 0),
        ('impersonation_level', 'I', 0),
        ('smb_create_flags', 'Q', 0),
        ('_rsv', 'Q', 0),
        ('desired_access', 'I', 0),
        ('file_attributes', 'I', 0),
        ('share_access', 'I', 0),
        ('create_disposition', 'I', 0),
        ('create_options', 'I', 0),
        ('name_offset', 'H', 0),
        ('name_length', 'H', 0),
        ('create_contexts_offset', 'I', 0),
        ('create_contexts_length', 'I', 0),
    ]

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        start = self.name_offset - self.__hdr_len__
        self.file_name = buf[start:start + self.name_length]
        self.data = b''
```

- [ ] **Step 4: Register commands in _cmdsw**

```python
SMB2._cmdsw[SMB2_CMD_SESSION_SETUP] = SMB2SessionSetup
SMB2._cmdsw[SMB2_CMD_TREE_CONNECT] = SMB2TreeConnect
SMB2._cmdsw[SMB2_CMD_CREATE] = SMB2Create
```

- [ ] **Step 5: Run tests to verify**

Run: `pytest dpkt/smb2.py -v`  
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 SessionSetup, TreeConnect, Create commands"
```

---

### Task 4: SMB2Close + SMB2Read (file_data extraction)

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Write failing tests for Close and Read**

```python
def test_smb2_close():
    buf = unhexlify(
        'fe534d4240000000000000000600000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '18000000ffffffffffffffffffffffffffffffff'  # Close request
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_CLOSE
    assert isinstance(smb2.data, SMB2Close)

def test_smb2_read_response():
    """Test SMB2 READ response with file data extraction."""
    buf = unhexlify(
        'fe534d4240000000000000000800000000000000'
        '0000000000000000000000000100000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '110050000000100000000000'                    # Read response header
        '0000000048656c6c6f20576f726c64'              # "Hello World"
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_READ
    assert isinstance(smb2.data, SMB2Read)
    assert smb2.data.file_data == b'Hello World'
```

- [ ] **Step 2: Run to confirm failure**

Run: `pytest dpkt/smb2.py::test_smb2_close dpkt/smb2.py::test_smb2_read_response -v`  
Expected: FAIL

- [ ] **Step 3: Implement Close and Read classes**

```python
class SMB2Close(dpkt.Packet):
    """SMB2 CLOSE Request."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 24),
        ('flags', 'H', 0),
        ('_rsv', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
    ]


class SMB2Read(dpkt.Packet):
    """SMB2 READ Request/Response."""
    __byte_order__ = '<'

    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB2Read, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        # Detect request vs response by StructureSize
        struct_size = struct.unpack('<H', buf[0:2])[0]
        if struct_size == 17:
            self._unpack_response(buf)
        elif struct_size == 49:
            self._unpack_request(buf)
        else:
            raise dpkt.UnpackError('invalid SMB2Read StructureSize')

    def _unpack_request(self, buf):
        self.struct_size, self.padding, self.data_offset, self.length = \
            struct.unpack('<HBHI', buf[0:10])
        self.offset = struct.unpack('<Q', buf[10:18])[0]
        self.file_id = buf[18:34]
        self.channel, self.remaining = struct.unpack('<II', buf[34:42])
        self.channel_info_offset, self.channel_info_length = struct.unpack('<HH', buf[42:46])
        self.flags = struct.unpack('<I', buf[46:50])[0] if len(buf) >= 50 else 0
        self.data = b''

    def _unpack_response(self, buf):
        self.struct_size, self.data_offset = struct.unpack('<HB', buf[0:3])
        self._rsv = buf[3]
        self.data_length, self.data_remaining = struct.unpack('<II', buf[4:12])
        self._rsv2 = buf[12:16]
        start = self.data_offset - self.__hdr_len__ if hasattr(self, '__hdr_len__') else self.data_offset
        self.file_data = buf[start:start + self.data_length]
        self.data = b''

    def __bytes__(self):
        if self.file_data:
            return self._pack_response()
        return self._pack_request()

    def _pack_response(self):
        hdr = struct.pack('<HBBI4s', self.struct_size, self.data_offset if hasattr(self, 'data_offset') else 0,
                          self._rsv if hasattr(self, '_rsv') else 0,
                          self.data_length if hasattr(self, 'data_length') else 0,
                          self.data_remaining if hasattr(self, 'data_remaining') else 0,
                          self._rsv2 if hasattr(self, '_rsv2') else b'\x00' * 4)
        return hdr + self.file_data

    def _pack_request(self):
        return struct.pack('<HBHIQ16sIIHHI',
            self.struct_size if hasattr(self, 'struct_size') else 49,
            self.padding if hasattr(self, 'padding') else 0,
            self.data_offset if hasattr(self, 'data_offset') else 0,
            self.length if hasattr(self, 'length') else 0,
            self.offset if hasattr(self, 'offset') else 0,
            self.file_id if hasattr(self, 'file_id') else b'\xff' * 16,
            self.channel if hasattr(self, 'channel') else 0,
            self.remaining if hasattr(self, 'remaining') else 0,
            self.channel_info_offset if hasattr(self, 'channel_info_offset') else 0,
            self.channel_info_length if hasattr(self, 'channel_info_length') else 0,
            self.flags if hasattr(self, 'flags') else 0)
```

- [ ] **Step 4: Register and run tests**

```python
SMB2._cmdsw[SMB2_CMD_CLOSE] = SMB2Close
SMB2._cmdsw[SMB2_CMD_READ] = SMB2Read
```

Run: `pytest dpkt/smb2.py -v`  
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 Close + Read commands with file_data extraction"
```

---

### Task 5: SMB2Write (file_data in request)

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Write failing test for Write with file data**

```python
def test_smb2_write_request():
    """Test SMB2 WRITE request with file data."""
    buf = unhexlify(
        'fe534d4240000000000000000900000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '3100700000001000000000000000000000000000'  # Write request
        '0000ffffffffffffffffffffffffffffffff0000'
        '0000000000000000000000000000000000000000'
        '48656c6c6f20576f726c64'                      # "Hello World"
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_WRITE
    assert isinstance(smb2.data, SMB2Write)
    assert smb2.data.file_data == b'Hello World'
```

- [ ] **Step 2: Run to confirm failure**

Run: `pytest dpkt/smb2.py::test_smb2_write_request -v`  
Expected: FAIL

- [ ] **Step 3: Implement SMB2Write**

```python
class SMB2Write(dpkt.Packet):
    """SMB2 WRITE Request."""
    __byte_order__ = '<'

    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB2Write, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        self.struct_size, self.data_offset, self.length = struct.unpack('<HHI', buf[0:8])
        self.offset = struct.unpack('<Q', buf[8:16])[0]
        self.file_id = buf[16:32]
        self.channel, self.remaining = struct.unpack('<II', buf[32:40])
        self.channel_info_offset, self.channel_info_length = struct.unpack('<HH', buf[40:44])
        self.flags = struct.unpack('<I', buf[44:48])[0]
        start = self.data_offset
        self.file_data = buf[start:start + self.length]
        self.data = b''

    def __bytes__(self):
        hdr = struct.pack('<HHIQ16sIIHHI',
            self.struct_size if hasattr(self, 'struct_size') else 49,
            self.data_offset if hasattr(self, 'data_offset') else 0,
            self.length if hasattr(self, 'length') else len(self.file_data),
            self.offset if hasattr(self, 'offset') else 0,
            self.file_id if hasattr(self, 'file_id') else b'\xff' * 16,
            self.channel if hasattr(self, 'channel') else 0,
            self.remaining if hasattr(self, 'remaining') else 0,
            self.channel_info_offset if hasattr(self, 'channel_info_offset') else 0,
            self.channel_info_length if hasattr(self, 'channel_info_length') else 0,
            self.flags if hasattr(self, 'flags') else 0)
        return hdr + self.file_data
```

- [ ] **Step 4: Register and run tests**

```python
SMB2._cmdsw[SMB2_CMD_WRITE] = SMB2Write
```

Run: `pytest dpkt/smb2.py -v`  
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 Write command with file_data extraction"
```

---

### Task 6: SMB2 _mod_init() + Unknown Command Handling

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Write test for _mod_init auto-loading**

```python
def test_smb2_mod_init():
    """Verify _mod_init() populates _cmdsw from SMB2_CMD_* constants."""
    # All 7 core commands should be registered
    assert SMB2_CMD_NEGOTIATE in SMB2._cmdsw
    assert SMB2_CMD_SESSION_SETUP in SMB2._cmdsw
    assert SMB2_CMD_TREE_CONNECT in SMB2._cmdsw
    assert SMB2_CMD_CREATE in SMB2._cmdsw
    assert SMB2_CMD_CLOSE in SMB2._cmdsw
    assert SMB2_CMD_READ in SMB2._cmdsw
    assert SMB2_CMD_WRITE in SMB2._cmdsw

def test_smb2_unknown_command():
    """Test unknown command falls back to raw bytes."""
    buf = unhexlify(
        'fe534d424000000000000000ff00000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        'deadbeef'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == 0x00FF  # unknown
    assert isinstance(smb2.data, bytes)
    assert smb2.data == b'\xde\xad\xbe\xef'
```

- [ ] **Step 2: Run to confirm failures**

Run: `pytest dpkt/smb2.py::test_smb2_mod_init dpkt/smb2.py::test_smb2_unknown_command -v`  
Expected: FAIL (for unknown_command: bytes in data should be fine already; for mod_init: need to verify auto-load works when imported via dpkt)

- [ ] **Step 3: Remove manual _cmdsw registrations, add _mod_init()**

Remove all manual `SMB2._cmdsw[...] = ...` lines. Add:

```python
def _mod_init():
    """Post-import hook: populate SMB2._cmdsw from SMB2_CMD_* constants."""
    for name, val in list(globals().items()):
        if name.startswith('SMB2_CMD_'):
            cls_name = 'SMB2' + name[len('SMB2_CMD_'):].title().replace('_', '')
            cmd_cls = globals().get(cls_name)
            if cmd_cls is not None and isinstance(cmd_cls, type):
                SMB2._cmdsw[val] = cmd_cls
```

- [ ] **Step 4: Run all tests to verify**

Run: `pytest dpkt/smb2.py -v`  
Expected: all PASS (including _mod_init test and unknown command test)

- [ ] **Step 5: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 _mod_init() auto-loading + unknown command fallback"
```

---

# Phase 1 Complete

**Checkpoint:** 7 SMB2 core commands working. File data extraction from Read/Write. Auto-loading via `_mod_init()`. All tests pass.

---

## Phase 2: SMB2 Remaining Commands (Tasks 7–14)

### Task 7: SMB2Logoff + SMB2TreeDisconnect

**Files:**
- Modify: `dpkt/smb2.py`

(Simple commands with minimal bodies — each task follows the same test-first pattern)

- [ ] **Step 1: Add test for Logoff and TreeDisconnect**

```python
def test_smb2_logoff():
    buf = unhexlify(
        'fe534d4240000000000000000200000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '040000000000'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_LOGOFF
    assert isinstance(smb2.data, SMB2Logoff)

def test_smb2_tree_disconnect():
    buf = unhexlify(
        'fe534d4240000000000000000400000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '040000000000'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_TREE_DISCONNECT
    assert isinstance(smb2.data, SMB2TreeDisconnect)
```

- [ ] **Step 2: Run to confirm failure → implement classes → run tests → pass**

```python
class SMB2Logoff(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 4),
        ('_rsv', 'H', 0),
    ]


class SMB2TreeDisconnect(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 4),
        ('_rsv', 'H', 0),
    ]
```

- [ ] **Step 3: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 Logoff and TreeDisconnect commands"
```

---

### Task 8: SMB2Flush + SMB2Lock

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Write tests → implement → verify → commit**

```python
class SMB2Flush(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 24),
        ('_rsv1', 'H', 0),
        ('_rsv2', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
    ]


class SMB2Lock(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 48),
        ('lock_count', 'H', 0),
        ('lock_sequence', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
    ]

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.locks = []
        off = self.__hdr_len__
        for _ in range(self.lock_count):
            lock = struct.unpack('<QQII', buf[off:off + 24])
            self.locks.append({
                'offset': lock[0], 'length': lock[1], 'flags': lock[2], '_rsv': lock[3]
            })
            off += 24
        self.data = b''
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 Flush and Lock commands"
```

---

### Task 9: SMB2IOCtl

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Add test**

```python
def test_smb2_ioctl():
    buf = unhexlify(
        'fe534d4240000000000000000b00000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '390000000000000000000000ffffffffffffffff'
        'ffffffffffffffff780000000000000000000000'
        '0000000000000000000000000000000000000000'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_IOCTL
    assert isinstance(smb2.data, SMB2IOCtl)
    assert smb2.data.struct_size == 57
```

- [ ] **Step 2: Implement**

```python
class SMB2IOCtl(dpkt.Packet):
    """SMB2 IOCTL Request/Response."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 57),
        ('_rsv', 'H', 0),
        ('ctl_code', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
    ]

    def __init__(self, *args, **kwargs):
        self.in_data = b''
        self.out_data = b''
        super(SMB2IOCtl, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = self.__hdr_len__
        self.in_offset, self.in_length = struct.unpack('<II', buf[off:off+8]); off += 8
        self.max_in_size, self.out_offset = struct.unpack('<II', buf[off:off+8]); off += 8
        self.out_length, self.max_out_size = struct.unpack('<II', buf[off:off+8]); off += 8
        self.flags = struct.unpack('<I', buf[off:off+4])[0]; off += 4
        self._rsv2 = buf[off:off+4]
        if self.in_length:
            self.in_data = buf[self.in_offset:self.in_offset + self.in_length]
        if self.out_length:
            self.out_data = buf[self.out_offset:self.out_offset + self.out_length]
        self.data = b''
```

- [ ] **Step 3: Run tests → commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 IOCTL command"
```

---

### Task 10: SMB2Cancel + SMB2Echo

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Implement and test**

```python
class SMB2Cancel(dpkt.Packet):
    """SMB2 CANCEL — no body, just the 64-byte header. Parsing stops at header level."""
    __byte_order__ = '<'
    __hdr__ = [('struct_size', 'H', 4)]

class SMB2Echo(dpkt.Packet):
    """SMB2 ECHO Request/Response."""
    __byte_order__ = '<'
    __hdr__ = [('struct_size', 'H', 4)]

def test_smb2_cancel_echo():
    for cmd_code, cls in [(SMB2_CMD_CANCEL, SMB2Cancel), (SMB2_CMD_ECHO, SMB2Echo)]:
        buf = b'\xfeSMB' + b'\x40\x00' + b'\x00' * 56 + struct.pack('<H', cmd_code) + b'\x00' * 2 + b'\x00' * 40 + b'\x04\x00\x00\x00'
        smb2 = SMB2(buf)
        assert isinstance(smb2.data, cls)
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 Cancel and Echo commands"
```

---

### Task 11: SMB2QueryDirectory

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Implement with FileInformation parsing**

```python
class SMB2QueryDirectory(dpkt.Packet):
    """SMB2 QUERY_DIRECTORY Request/Response."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 33),
        ('file_info_class', 'B', 0),
        ('flags', 'B', 0),
        ('file_index', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
    ]

    def __init__(self, *args, **kwargs):
        self.file_name = b''
        self.entries = []
        super(SMB2QueryDirectory, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = self.__hdr_len__
        self.file_name_offset, self.file_name_length = struct.unpack('<HH', buf[off:off+4]); off += 4
        self.output_offset, self.output_length = struct.unpack('<II', buf[off:off+8])
        if self.file_name_length:
            self.file_name = buf[self.file_name_offset:self.file_name_offset + self.file_name_length]
        self.data = buf[self.output_offset:self.output_offset + self.output_length]
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 QueryDirectory command"
```

---

### Task 12: SMB2ChangeNotify + SMB2OplockBreak

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Implement both commands**

```python
class SMB2ChangeNotify(dpkt.Packet):
    """SMB2 CHANGE_NOTIFY Request."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 32),
        ('flags', 'H', 0),
        ('output_buffer_length', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
        ('completion_filter', 'I', 0),
        ('_rsv', 'I', 0),
    ]

class SMB2OplockBreak(dpkt.Packet):
    """SMB2 OPLOCK_BREAK Notification/Response."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 24),
        ('oplock_level', 'B', 0),
        ('_rsv', 'B', 0),
        ('_rsv2', 'I', 0),
        ('file_id', '16s', b'\xff' * 16),
    ]
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 ChangeNotify and OplockBreak commands"
```

---

### Task 13: SMB2QueryInfo + SMB2SetInfo

**Files:**
- Modify: `dpkt/smb2.py`

- [ ] **Step 1: Implement with InfoType support**

```python
class SMB2QueryInfo(dpkt.Packet):
    """SMB2 QUERY_INFO Request."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 41),
        ('info_type', 'B', 0),
        ('file_info_class', 'B', 0),
    ]
    def __init__(self, *args, **kwargs):
        self.output_data = b''
        self.input_data = b''
        super(SMB2QueryInfo, self).__init__(*args, **kwargs)
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = self.__hdr_len__
        self.output_buffer_length, self.input_buffer_offset = struct.unpack('<IH', buf[off:off+6]); off += 6
        self._rsv, self.input_buffer_length = struct.unpack('<HI', buf[off:off+6]); off += 6
        self.additional_info, self.flags = struct.unpack('<II', buf[off:off+8]); off += 8
        self.file_id = buf[off:off+16]
        if self.input_buffer_length:
            self.input_data = buf[self.input_buffer_offset:self.input_buffer_offset + self.input_buffer_length]

class SMB2SetInfo(dpkt.Packet):
    """SMB2 SET_INFO Request."""
    __byte_order__ = '<'
    __hdr__ = [
        ('struct_size', 'H', 33),
        ('info_type', 'B', 0),
        ('file_info_class', 'B', 0),
    ]
    def __init__(self, *args, **kwargs):
        self.buffer_data = b''
        super(SMB2SetInfo, self).__init__(*args, **kwargs)
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = self.__hdr_len__
        self.buffer_length, self.buffer_offset = struct.unpack('<IH', buf[off:off+6]); off += 6
        self._rsv, self.additional_info = struct.unpack('<HI', buf[off:off+6]); off += 6
        self.file_id = buf[off:off+16]
        self._rsv2 = struct.unpack('<I', buf[off+16:off+20])[0]
        if self.buffer_length:
            self.buffer_data = buf[self.buffer_offset:self.buffer_offset + self.buffer_length]
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb2.py
git commit -m "feat: add SMB2 QueryInfo and SetInfo commands"
```

---

# Phase 2 Complete

**Checkpoint:** All 19 SMB2 commands implemented and tested.

---

## Phase 3: NBSS Wrapper + Integration (Tasks 15–16)

### Task 15: Create nbss.py

**Files:**
- Create: `dpkt/nbss.py`

- [ ] **Step 1: Write NBSS class with test**

```python
# dpkt/nbss.py
# -*- coding: utf-8 -*-
"""NetBIOS Session Service."""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt


class NBSS(dpkt.Packet):
    """NetBIOS Session Service wrapper.

    Attributes:
        __hdr__: NBSS 4-byte header
            type: (int) Message type (0x00 = Session Message)
            _len: (bytes) 24-bit big-endian length
    """
    __hdr__ = [
        ('type', 'B', 0),
        ('_len', '3s', b'\x00' * 3),
    ]

    @property
    def length(self):
        return (self._len[0] << 16) | (self._len[1] << 8) | self._len[2]

    @length.setter
    def length(self, v):
        self._len = bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = buf[self.__hdr_len__:self.__hdr_len__ + self.length]


def test_nbss():
    """Test NBSS header parsing."""
    from binascii import unhexlify
    buf = unhexlify('0000002aff534d42720000000000')
    nbss = NBSS(buf)
    assert nbss.type == 0x00  # Session Message
    assert nbss.length == 42
    assert len(nbss.data) == 42
    assert nbss.data[0:4] == b'\xffSMB'

def test_nbss_roundtrip():
    """Test NBSS construct → bytes → parse."""
    payload = b'\xffSMB' + b'\x00' * 28
    nbss = NBSS(type=0, data=payload)
    nbss.length = len(payload)
    data = bytes(nbss)
    assert len(data) == 4 + len(payload)
    parsed = NBSS(data)
    assert parsed.length == len(payload)
    assert parsed.data == payload
```

- [ ] **Step 2: Run tests → commit**

```bash
git add dpkt/nbss.py
git commit -m "feat: add NBSS NetBIOS Session Service wrapper"
```

---

### Task 16: Update dpkt/__init__.py

**Files:**
- Modify: `dpkt/__init__.py`

- [ ] **Step 1: Add imports in alphabetical order**

```python
# After line 38 (from . import netbios) and before line 39 (from . import netflow):
from . import nbss

# After line 67 (from . import smb) and before line 68 (from . import ssl):
from . import smb2
```

- [ ] **Step 2: Verify imports work**

Run: `python -c "import dpkt; print(dir(dpkt)); print(hasattr(dpkt, 'smb2')); print(hasattr(dpkt, 'nbss'))"`  
Expected: True for both

- [ ] **Step 3: Run full test suite to ensure no breakage**

Run: `pytest dpkt/ -x -q`  
Expected: all existing tests still pass

- [ ] **Step 4: Commit**

```bash
git add dpkt/__init__.py
git commit -m "feat: register nbss and smb2 modules in dpkt package"
```

---

# Phase 3 Complete

**Checkpoint:** NBSS wrapper functional. smb2 and nbss importable via `import dpkt`.

---

## Phase 4: SMB1 Enhancement (Tasks 17–24)

### Task 17: SMB1Command Base Class + ANDX Chain

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Write test for ANDX chain parsing**

```python
def test_smb1_andx_chain():
    """Test SMB1 ANDX chain with NTCreateAndX + ReadAndX."""
    from binascii import unhexlify
    buf = unhexlify(
        'ff534d42750000000000000000000000000000'  # SMB header (TreeConnectAndX)
        '000000000000000000000000000000000000'
        '0700'  # WordCount=7, then parameter words...
        'ff00'  # AndXCommand=0xFF (no ANDX), AndXReserved=0
        '0000'  # AndXOffset=0
    )
    smb = SMB(buf)
    assert len(smb.commands) == 1
```

- [ ] **Step 2: Add SMB1Command base class**

```python
class SMB1Command(dpkt.Packet):
    """Base class for all SMB1 commands using WordCount/ByteCount pattern."""
    __byte_order__ = '<'

    def __init__(self, *args, **kwargs):
        self.andx_command = 0xFF
        self.andx_offset = 0
        super(SMB1Command, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        self.word_count = buf[0]
        # Parameter words (each 2 bytes LE)
        params_start = 1
        params_end = params_start + self.word_count * 2
        self._params = buf[params_start:params_end]
        # ByteCount (2 bytes LE)
        bc_off = params_end
        self.byte_count = struct.unpack('<H', buf[bc_off:bc_off + 2])[0]
        data_off = bc_off + 2
        self._raw_data = buf[data_off:data_off + self.byte_count]
        self.data = b''
```

- [ ] **Step 3: Add ANDX chain to SMB.unpack()**

```python
class SMB(dpkt.Packet):
    _cmdsw = {}

    def __init__(self, *args, **kwargs):
        self.commands = []
        super(SMB, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.commands = []
        offset = self.__hdr_len__
        next_cmd = self.cmd
        while True:
            cmd_cls = self._cmdsw.get(next_cmd)
            if cmd_cls is None:
                break
            cmd = cmd_cls(buf[offset:])
            self.commands.append(cmd)
            next_cmd = cmd.andx_command
            andx_off = cmd.andx_offset
            if next_cmd == 0xFF or andx_off == 0:
                break
            offset = offset + andx_off
        self.data = b''
```

- [ ] **Step 4: Run tests → commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add SMB1Command base class and ANDX chain parsing"
```

---

### Task 18: SMB1 Core Commands (Negotiate, SessionSetupAndX, TreeConnectAndX)

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Define SMB1 command constants**

```python
SMB_CMD_CREATE_DIRECTORY = 0x00
SMB_CMD_CLOSE = 0x04
SMB_CMD_TRANS2 = 0x25
SMB_CMD_OPEN_ANDX = 0x2D
SMB_CMD_READ_ANDX = 0x2E
SMB_CMD_WRITE_ANDX = 0x2F
SMB_CMD_TRANS = 0x32
SMB_CMD_LOGOFF_ANDX = 0x70
SMB_CMD_TREE_DISCONNECT = 0x71
SMB_CMD_NEGOTIATE = 0x72
SMB_CMD_SESSION_SETUP_ANDX = 0x73
SMB_CMD_ECHO = 0x74
SMB_CMD_TREE_CONNECT_ANDX = 0x75
SMB_CMD_NT_TRANS = 0xA0
SMB_CMD_NT_TRANS_SECONDARY = 0xA1
SMB_CMD_NT_CREATE_ANDX = 0xA2
SMB_CMD_OPEN = 0xC0
```

- [ ] **Step 2: Implement the three core commands**

```python
class SMB1Negotiate(SMB1Command):
    """SMB1 Negotiate Protocol."""
    def unpack(self, buf):
        self.word_count = buf[0]
        # Request: WordCount=0 (response: WordCount=17)
        if self.word_count == 0:
            self._params = b''
        else:
            self._params = buf[1:1 + self.word_count * 2]
        bc_off = 1 + self.word_count * 2
        self.byte_count = struct.unpack('<H', buf[bc_off:bc_off + 2])[0]
        data_off = bc_off + 2
        self._raw_data = buf[data_off:data_off + self.byte_count]
        # Extract dialects from _raw_data if present
        self.dialects = []
        if self.word_count == 0 and self._raw_data:
            d = self._raw_data
            while d:
                try:
                    # Null-terminated ASCII dialect strings
                    end = d.index(b'\x00')
                    self.dialects.append(d[:end])
                    d = d[end+1:]
                except ValueError:
                    if len(d) > 0:
                        self.dialects.append(d)
                    break
        self.data = b''

class SMB1SessionSetupAndX(SMB1Command):
    """SMB1 Session Setup AndX."""
    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]

class SMB1TreeConnectAndX(SMB1Command):
    """SMB1 Tree Connect AndX."""
    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
```

- [ ] **Step 3: Commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add SMB1 core commands (Negotiate, SessionSetup, TreeConnect)"
```

---

### Task 19: SMB1 NTCreateAndX + Close (with file name extraction)

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Implement NTCreateAndX with file name + Close**

```python
class SMB1NTCreateAndX(SMB1Command):
    """SMB1 NT Create AndX."""
    def __init__(self, *args, **kwargs):
        self.file_name = b''
        super(SMB1NTCreateAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        if len(self._params) >= 28:
            self.name_length = struct.unpack('<H', self._params[20:22])[0]
            # File name follows the parameter block and a 1-byte pad/buffer type
            if self.name_length and len(self._raw_data) >= self.name_length + 1:
                self.file_name = self._raw_data[1:1 + self.name_length]

class SMB1Close(SMB1Command):
    """SMB1 Close."""
    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        # Simple Close: WordCount=3, no ANDX
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add SMB1 NTCreateAndX (file name) and Close commands"
```

---

### Task 20: SMB1 ReadAndX + WriteAndX (file_data extraction)

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Implement both with file_data**

```python
class SMB1ReadAndX(SMB1Command):
    """SMB1 Read AndX."""
    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB1ReadAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        # Response: data follows the ByteCount area
        if self.byte_count:
            self.file_data = self._raw_data
        self.data = b''

class SMB1WriteAndX(SMB1Command):
    """SMB1 Write AndX."""
    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB1WriteAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        if len(self._params) >= 28:
            self.data_length = struct.unpack('<H', self._params[20:22])[0]
            self.data_offset = struct.unpack('<H', self._params[22:24])[0]
        # Request: file data is in the _raw_data at data_offset
        if self.byte_count:
            self.file_data = self._raw_data
        self.data = b''
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add SMB1 ReadAndX and WriteAndX with file_data extraction"
```

---

### Task 21: SMB1 Remaining Commands (Open, OpenAndX, LogoffAndX, Echo, TreeDisconnect)

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Implement all remaining commands**

```python
class SMB1Open(SMB1Command):
    """SMB1 Open (legacy)."""
    pass  # Uses base SMB1Command.unpack

class SMB1OpenAndX(SMB1Command):
    """SMB1 Open AndX."""
    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]

class SMB1LogoffAndX(SMB1Command):
    """SMB1 Logoff AndX."""
    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 2:
            self.andx_command = self._params[0]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]

class SMB1Echo(SMB1Command):
    """SMB1 Echo."""
    pass  # Uses base SMB1Command.unpack

class SMB1TreeDisconnect(SMB1Command):
    """SMB1 Tree Disconnect."""
    pass  # Uses base SMB1Command.unpack
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add remaining SMB1 commands (Open, Echo, Logoff, TreeDisconnect)"
```

---

### Task 22: SMB1 Trans/NTTrans Sub-Commands

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Implement Trans2, Trans, NTTrans with sub-command dispatch**

```python
class SMB1Trans2(SMB1Command):
    """SMB1 Transaction2 (extended)."""
    _subcmdsw = {}

    def __init__(self, *args, **kwargs):
        self.sub_cmd = None
        super(SMB1Trans2, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 30:
            self.total_param_count, self.total_data_count = struct.unpack('<HH', self._params[0:4])
            self.max_param_count, self.max_data_count = struct.unpack('<HH', self._params[4:8])
            self.max_setup_count = self._params[8]
            self._rsv = self._params[9]
            self.flags = struct.unpack('<H', self._params[10:12])[0]
            self.timeout = struct.unpack('<I', self._params[12:16])[0]
            self._rsv2 = struct.unpack('<H', self._params[16:18])[0]
            self.param_count, self.param_offset = struct.unpack('<HH', self._params[18:22])
            self.data_count, self.data_offset = struct.unpack('<HH', self._params[22:26])
            setup_count = self._params[26]
            self._rsv3 = self._params[27]
            self.setup = self._params[28:28 + setup_count * 2]
            # Sub-command from first Setup word
            if setup_count >= 1:
                self.sub_cmd = struct.unpack('<H', self.setup[0:2])[0]
            # Named pipe / file name from parameters
            self.param_data = self._raw_data[self.param_offset - self.__hdr_len__:
                                              self.param_offset - self.__hdr_len__ + self.param_count] if self.param_count else b''

class SMB1Trans(SMB1Command):
    """SMB1 Transaction (original). Follows same pattern as Trans2."""
    _subcmdsw = {}
    def unpack(self, buf):
        # Similar to Trans2 with slightly different offset layout
        SMB1Command.unpack(self, buf)
        self.data = b''

class SMB1NTTrans(SMB1Command):
    """SMB1 NT Transaction."""
    _subcmdsw = {}
    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 38:
            self.setup_count = self._params[32]
            self.function_code = struct.unpack('<H', self._params[34:36])[0] if self.setup_count >= 1 else 0
        self.data = b''

class SMB1NTTransSecondary(SMB1Command):
    """SMB1 NT Transaction Secondary (continuation)."""
    pass
```

- [ ] **Step 2: Commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add SMB1 Trans2/Trans/NTTrans sub-command dispatch"
```

---

### Task 23: SMB1 _mod_init() + Backward Compatibility

**Files:**
- Modify: `dpkt/smb.py`

- [ ] **Step 1: Add _mod_init() for SMB1 auto-loading**

```python
def _mod_init():
    """Post-import hook: populate SMB._cmdsw from SMB_CMD_* constants."""
    for name, val in list(globals().items()):
        if name.startswith('SMB_CMD_'):
            cls_name = 'SMB1' + name[len('SMB_CMD_'):].title().replace('_', '')
            cmd_cls = globals().get(cls_name)
            if cmd_cls is not None and isinstance(cmd_cls, type):
                SMB._cmdsw[val] = cmd_cls
```

- [ ] **Step 2: Verify existing test_smb() still passes unchanged**

Run: `pytest dpkt/smb.py::test_smb -v`  
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `pytest dpkt/ -v`  
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add dpkt/smb.py
git commit -m "feat: add SMB1 _mod_init() + verify backward compatibility"
```

---

# Phase 4 Complete

**Checkpoint:** Full SMB1 + SMB2 + NBSS support. All ~60 tests pass. Backward compatible.

---

## Final Verification

Run: `pytest dpkt/ -v`
Expected: all tests pass, including existing + new SMB tests (.eg., existing smb tests, new smb2 tests, nbss tests)

Run: `python -c "import dpkt; print(hasattr(dpkt, 'smb2'), hasattr(dpkt, 'nbss'))"`
Expected: True True

Run: `python -c "from dpkt.smb2 import SMB2, SMB2Read; s = SMB2(); print(s.__hdr_len__)"`
Expected: 64
```

