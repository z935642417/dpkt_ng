# dpkt SMB Protocol Support — Design Specification

**Date:** 2026-04-29  
**Status:** Draft  
**Author:** z935642417  
**Scope:** dpkt_ng — SMB1 + SMB2 protocol parsing enhancement

---

## 1. Overview

Enhance dpkt's SMB protocol parsing from a basic SMBv1 32-byte header-only implementation to full SMB1 and SMB2 protocol support with deep semantic command parsing, ANDX chain handling, and file content extraction. This feature targets **PCAP offline analysis and forensics** use cases.

### 1.1 Current State

- `dpkt/smb.py` exists, parses SMB1 32-byte fixed header only
- No SMB2/SMB3 support
- No command parsing, no ANDX chain, no file data extraction
- No transport-layer (NetBIOS/Direct TCP) integration

### 1.2 Goals

| Goal | Description |
|------|-------------|
| SMB2 support | Full 64-byte header + all 19 standard commands |
| SMB1 enhancement | ANDX chain + 16 command parsers + Trans sub-commands |
| File extraction | Extract file payload from READ/WRITE commands |
| Transport | NBSS (NetBIOS Session Service) + Direct TCP |
| Integration | Follow dpkt patterns: `_cmdsw`, `_mod_init()`, inline tests |

---

## 2. File Organization

```
dpkt/
├── smb.py          # Enhanced: SMB1 header + ANDX chain + command dispatch
├── smb2.py         # New:      SMB2 header + 19 command parsers
└── nbss.py         # New:      NetBIOS Session Service wrapper
```

### 2.1 Rationale

- **Separate files per protocol version** — SMB1 and SMB2 have fundamentally different header structures (32 vs 64 bytes), command sets, and transport semantics. Splitting avoids version-conditional logic and follows dpkt's module-per-protocol convention.
- **nbss.py as separate module** — NBSS is a transport wrapper used by both SMB1 and SMB2, not part of either protocol. Treating it as its own `dpkt.Packet` subclass mirrors the PPPoE/PPP split.
- **No shared constants file** — Following dpkt's existing convention of defining constants in the same module as the code that uses them. If duplication becomes painful, a `_smb_common.py` can be extracted later.

---

## 3. SMB2 Design (`dpkt/smb2.py`)

### 3.1 Header: `class SMB2(dpkt.Packet)`

64-byte fixed header, little-endian (`__byte_order__ = '<'`), protocol magic `\xfeSMB`.

```python
class SMB2(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('proto', '4s', b'\xfeSMB'),      #  0: Protocol ID
        ('hdr_len', 'H', 64),              #  4: StructureSize
        ('credit_charge', 'H', 0),         #  6: CreditCharge
        ('_chan_seq', 'I', 0),             #  8: ChannelSequence/Reserved (3 bytes) + Status (1 byte)
        ('cmd', 'H', 0),                   # 12: Command (dispatch key)
        ('credit_req', 'H', 0),           # 14: CreditRequest/Response
        ('_flags', 'I', 0),               # 16: Flags (bit_fields)
        ('next_cmd', 'I', 0),             # 20: NextCommand (compound)
        ('mid', 'Q', 0),                  # 24: MessageId
        ('pid', 'I', 0),                  # 32: ProcessId (reserved in 3.x)
        ('tid', 'I', 0),                  # 36: TreeId
        ('sid', 'Q', 0),                  # 40: SessionId
        ('sig', '16s', b'\x00' * 16),    # 48: Signature
    )
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

**Key design decisions:**

- `_chan_seq` as single `'I'` (4 bytes) — combines ChannelSequence (2 bytes, reserved), Reserved (1 byte), and NT Status field. The status can be exposed as `@property nt_status` splitting out the low byte.
- `_flags` uses `__bit_fields__` — follows TCP's `_off_flags` pattern for bitfield decomposition.
- `mid` uses `'Q'` (8 bytes unsigned) — SMB2 MessageId is 64-bit.

### 3.2 Command Dispatch

```python
class SMB2(dpkt.Packet):
    _cmdsw = {}  # {SMB2_CMD_READ: SMB2Read, ...}

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            cmd_cls = self._cmdsw[self.cmd]
            self.data = cmd_cls(buf[self.__hdr_len__:])
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf[self.__hdr_len__:]
```

**Dispatch pattern:** Same as `IP._protosw` and `AOE._cmdsw` — lookup table dispatch, fallback to raw bytes for unknown commands.

### 3.3 Command Class Hierarchy

```
SMB2Command(dpkt.Packet)          # Base: no __hdr__, manual unpack
├── SMB2Negotiate                 # Dialects → Capabilities
├── SMB2SessionSetup              # Auth blob → SessionFlags
├── SMB2Logoff
├── SMB2TreeConnect               # Share path → ShareType
├── SMB2TreeDisconnect
├── SMB2Create                    # File name + create opts → FileId
├── SMB2Close                     # FileId → Attributes
├── SMB2Flush                     # FileId
├── SMB2Read                      # FileId+Offset+Length → file_data
├── SMB2Write                     # FileId+Offset+file_data → Count
├── SMB2Lock                      # FileId+Locks
├── SMB2IOCtl                     # CtlCode+Input → Output
├── SMB2Cancel                    # (no body, handled in header)
├── SMB2Echo                      # (keep-alive)
├── SMB2QueryDirectory            # FileId+Pattern → FileInfo entries
├── SMB2ChangeNotify              # FileId+Flags
├── SMB2QueryInfo                 # FileId+InfoType → Info buffer
├── SMB2SetInfo                   # FileId+Info buffer
└── SMB2OplockBreak               # FileId+OplockLevel
```

### 3.4 SMB2Command Base Class

SMB2 commands use a **StructureSize** field (2 bytes LE) that encodes the fixed portion length. Request and response have different sizes.

```python
class SMB2Command(dpkt.Packet):
    """Base for all SMB2 commands. Parses StructureSize then delegates."""
    __byte_order__ = '<'

    def unpack(self, buf):
        """Subclasses override this — no fixed __hdr__ since structures vary."""
        raise NotImplementedError
```

Each command subclass:
1. Reads `StructureSize` from `buf[0:2]`
2. Parses fixed fields with `struct.unpack()`
3. Handles variable buffers (e.g., file data, file names) from offsets within the buffer
4. Sets `self.data = b''` after consuming all bytes
5. Exposes semantic fields as `@property` where needed

### 3.5 File Data Extraction (Key Feature)

**SMB2Read (Response):**
```python
class SMB2Read(dpkt.Packet):
    __hdr__ = (
        ('struct_size', 'H', 17),       # Response size
        ('data_offset', 'B', 0),
        ('_rsv', 'B', 0),
        ('data_length', 'I', 0),
        ('data_remaining', 'I', 0),
        ('_rsv2', '4s', b'\x00' * 4),
    )

    file_data: bytes  # Extracted in unpack()

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        start = self.data_offset
        self.file_data = buf[start:start + self.data_length]
        self.data = b''
```

**SMB2Write (Request):**
```python
class SMB2Write(dpkt.Packet):
    __hdr__ = (
        ('struct_size', 'H', 49),       # Request size
        ('data_offset', 'H', 0),
        ('length', 'I', 0),
        ('offset', 'Q', 0),
        ('file_id', '16s', b'\xff' * 16),
        ('channel', 'I', 0),
        ('remaining', 'I', 0),
        ('channel_info_offset', 'H', 0),
        ('channel_info_length', 'H', 0),
        ('flags', 'I', 0),
    )

    file_data: bytes

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        start = self.data_offset
        self.file_data = buf[start:start + self.length]
        self.data = b''
```

### 3.6 Constants

Defined module-level with `SMB2_CMD_*` and `SMB2_FLAGS_*` prefixes (following dpkt convention):

```python
# Command codes
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

# Flags
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
SMB2_FLAGS_ASYNC_COMMAND = 0x00000002
SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
SMB2_FLAGS_SIGNED = 0x00000008
SMB2_FLAGS_PRIORITY_MASK = 0x00000070
SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
SMB2_FLAGS_REPLAY_OPERATION = 0x20000000
```

### 3.7 Auto-Loading

```python
def _mod_init():
    """Post-import hook: populate SMB2._cmdsw from SMB2_CMD_* constants."""
    import dpkt
    for name, val in globals().items():
        if name.startswith('SMB2_CMD_'):
            try:
                cls_name = name.replace('SMB2_CMD_', 'SMB2')
                cmd_cls = globals().get(cls_name)
                if cmd_cls:
                    SMB2._cmdsw[val] = cmd_cls
            except Exception:
                pass
```

---

## 4. SMB1 Enhancement (`dpkt/smb.py`)

### 4.1 Header Preservation

Existing `SMB.__hdr__` is preserved **unchanged** for backward compatibility. All existing tests must continue to pass.

### 4.2 ANDX Chain Parsing

```python
class SMB(dpkt.Packet):
    commands: list[SMB1Command] = []

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.commands = []
        offset = self.__hdr_len__
        next_cmd_code = self.cmd  # First command from SMB header
        while True:
            cmd = self._parse_cmd(buf, offset, next_cmd_code)
            self.commands.append(cmd)
            # Check for ANDX chain continuation
            next_cmd_code = getattr(cmd, 'andx_command', 0xFF)
            andx_off = getattr(cmd, 'andx_offset', 0)
            if next_cmd_code == 0xFF or andx_off == 0:
                break
            offset = offset + andx_off
        self.data = b''

    def _parse_cmd(self, buf, offset, cmd_code):
        """Parse a single SMB1 command at given offset.
        
        For the first command, cmd_code comes from the SMB header.
        For ANDX chain commands, cmd_code comes from the previous
        command's AndXCommand field.
        """
        cmd_cls = self._cmdsw.get(cmd_code)
        if cmd_cls is None:
            # Unknown command: store raw bytes
            return RawSMB1Command(buf[offset:])
        return cmd_cls(buf[offset:])
```

**Key challenge:** SMB1 commands use a **WordCount / ByteCount** variable-length structure rather than a fixed `__hdr__`. The ANDX chain pointer is at a fixed position within the parameter words.

**SMB1 `_mod_init()`** follows the same auto-loading pattern as SMB2 (Section 3.7), populating `SMB._cmdsw` from `SMB_CMD_*` constants. Existing `SMB_CMD_*` constants (`SMB_COM_CREATE_DIRECTORY`, etc.) are extended with any missing command codes.

### 4.3 SMB1Command Base Class

```python
class SMB1Command(dpkt.Packet):
    """Base class for all SMB1 commands. Uses WordCount/ByteCount pattern."""
    __byte_order__ = '<'

    # Subclasses define these
    _req_word_count: int = 0    # Expected WordCount
    _resp_word_count: int = 0   # If 0, WordCount varies

    def unpack(self, buf):
        self.word_count = buf[0]
        # Parameter words: buf[1 : 1 + word_count * 2]
        self._params = buf[1 : 1 + self.word_count * 2]
        # ByteCount: 2 LE bytes after parameters
        bc_off = 1 + self.word_count * 2
        self.byte_count = struct.unpack('<H', buf[bc_off:bc_off + 2])[0]
        # Data bytes
        data_off = bc_off + 2
        self._raw_data = buf[data_off:data_off + self.byte_count]
        self.data = b''
```

### 4.4 SMB1 Command List

| Code | Class | Key Fields |
|------|-------|------------|
| `0x72` | SMB1Negotiate | Dialects, Capabilities |
| `0x73` | SMB1SessionSetupAndX | Auth, NativeOS, NativeLanMan |
| `0x75` | SMB1TreeConnectAndX | Share path, Service |
| `0xA2` | SMB1NTCreateAndX | File name, DesiredAccess, CreateDisposition |
| `0x2E` | SMB1ReadAndX | Fid, Offset, MaxCount → file_data |
| `0x2F` | SMB1WriteAndX | Fid, Offset, Data → file_data |
| `0x04` | SMB1Close | Fid → LastWrite |
| `0x71` | SMB1TreeDisconnect | (none) |
| `0x25` | SMB1Trans2 | Sub-command dispatch |
| `0x32` | SMB1Trans | Sub-command dispatch |
| `0xA0` | SMB1NTTrans | Sub-command dispatch |
| `0xA1` | SMB1NTTransSecondary | Continuation of NTTrans |
| `0xC0` | SMB1Open | File name, Mode |
| `0x2D` | SMB1OpenAndX | File name, Flags |
| `0x70` | SMB1LogoffAndX | (none) |
| `0x74` | SMB1Echo | EchoCount, Data |

### 4.5 Trans/NTTrans Sub-Command Dispatch

`Trans2`, `Trans`, and `NTTrans` carry a **Setup** word array followed by a sub-command code. Each has its own `_subcmdsw` dict for secondary dispatch.

```python
class SMB1Trans2(SMB1Command):
    _subcmdsw = {}

    def unpack(self, buf):
        super().unpack(buf)
        # Parse Setup words → extract sub-command code
        # Trans2 sub-command is in the first Setup word (2 bytes LE)
        sub_cmd = struct.unpack('<H', self._params[0:2])[0]
        try:
            sub_cls = self._subcmdsw[sub_cmd]
            self.data = sub_cls(self._raw_data)
        except KeyError:
            self.data = self._raw_data
```

---

## 5. NBSS Wrapper (`dpkt/nbss.py`)

### 5.1 Design

NetBIOS Session Service provides a 4-byte header before the SMB PDU:

```python
class NBSS(dpkt.Packet):
    __hdr__ = (
        ('type', 'B', 0),              # 0x00 = Session Message
        ('_len', '3s', b'\x00' * 3),  # 24-bit big-endian length
    )

    @property
    def length(self) -> int:
        """Extract 24-bit big-endian length from 3-byte field."""
        return (self._len[0] << 16) | (self._len[1] << 8) | self._len[2]

    @length.setter
    def length(self, v: int):
        self._len = bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = buf[self.__hdr_len__:self.__hdr_len__ + self.length]
```

### 5.2 Usage Pattern

```python
# NetBIOS path (port 139):
nbss = dpkt.nbss.NBSS(tcp.data)
smb = dpkt.smb.SMB(nbss.data)

# Direct TCP path (port 445):
smb2 = dpkt.smb2.SMB2(tcp.data)
```

**No automatic port dispatch** — user constructs explicitly, following dpkt convention.

---

## 6. Integration with dpkt Layering

### 6.1 No Core Modifications

This design does NOT modify any existing dpkt files (TCP, IP, Ethernet, `__init__.py`) beyond adding `import smb2, nbss` to `dpkt/__init__.py`.

### 6.2 `_mod_init()` Auto-Loading

Both `smb.py` and `smb2.py` define `_mod_init()` functions called automatically by `dpkt/__init__.py`:

```python
# dpkt/__init__.py (existing behavior, no change needed)
for name, mod in list(sys.modules.items()):
    if name.startswith('dpkt.') and hasattr(mod, '_mod_init'):
        mod._mod_init()
```

### 6.3 Pretty-Print Support

```python
class SMB2(dpkt.Packet):
    __pprint_funcs__ = {
        'cmd': lambda v: smb2_cmd_str.get(v, str(v)),
    }
```

The existing `Packet.pprint()` recursively prints the layer chain, naturally including command data.

---

## 7. Testing Strategy

### 7.1 Test Pattern (follows dpkt convention)

- Tests are **inline** in each `.py` file, discovered by pytest (`python_files=*.py`, `python_functions=test`)
- Test data from `binascii.unhexlify()` or inline bytes literals
- Class-based test suites (`TestSMB2`, `TestSMB1AndX`, etc.)
- Cover: header unpack, command dispatch, parameter parsing, file data extraction, roundtrip (unpack→pack)

### 7.2 Test File Coverage

| File | Approx. Tests | Key Coverage |
|------|---------------|--------------|
| `smb2.py` | ~25 | Header fields, all 19 commands, file_data extraction, unknown commands, roundtrip |
| `smb.py` | ~30 | Existing SMB1 header (backward compat), ANDX chain (1/2/3 commands), all 16 commands, Trans sub-dispatch |
| `nbss.py` | ~6 | Type/length parsing, NBSS→SMB chaining, NBSS→SMB2 chaining, roundtrip |

### 7.3 Test Example

```python
# In smb2.py
def test_smb2_read_response():
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d4240000000000000000800000000000000'  # SMB2 header (64 bytes)
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '110050000000100000000000'                    # SMB2Read response
        '0000000048656c6c6f20576f726c64'              # "Hello World"
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_READ
    assert isinstance(smb2.data, SMB2Read)
    assert smb2.data.file_data == b'Hello World'
```

---

## 8. Implementation Plan (Phased)

### Phase 1: SMB2 Core (~400 lines)
- `smb2.py` with `SMB2` header class
- 7 core commands: Negotiate, SessionSetup, TreeConnect, Create, Close, Read, Write
- File data extraction working
- Constants + `_mod_init()`
- All tests passing

### Phase 2: SMB2 Complete (~300 lines)
- Remaining 12 commands: Logoff, TreeDisconnect, Flush, Lock, IOCTL, Cancel, Echo, QueryDirectory, ChangeNotify, QueryInfo, SetInfo, OplockBreak
- Edge case handling (truncated packets, unknown fields)
- Full test coverage

### Phase 3: NBSS + Integration (~100 lines)
- `nbss.py` with `NBSS` class
- Update `dpkt/__init__.py` to import `smb2`, `nbss`
- Integration tests with real pcap data

### Phase 4: SMB1 Enhancement (~500 lines)
- `SMB1Command` base class with WordCount/ByteCount parsing
- 16 SMB1 command subclasses
- ANDX chain parsing in `SMB.unpack()`
- Trans/NTTrans sub-command dispatch
- Backward compatible — all existing tests pass

**Total estimated: ~1300 lines of code, ~60 test functions**

---

## 9. Non-Goals (Out of Scope)

- SMB3.x support (multi-channel, encryption, RDMA) — separate future effort
- Session state tracking across packets — dpkt is stateless by design
- Automatic TCP port dispatch (modifying `tcp.py`) — user explicitly constructs
- SMB over QUIC — too new, requires QUIC support first
- Named pipe / RPC integration — separate protocol family
- SMB Signing verification — cryptographic operation, not parsing

---

## 10. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| SMB1 WordCount varies by dialect/flags | Use conditional parsing based on flags; document limitations |
| ANDX chain offset calculation errors | Test with multi-command chains; handle edge offsets gracefully |
| SMB2 StructureSize mismatch between versions | Validate StructureSize; raise UnpackError on mismatch |
| Large file data in single packet | Use offset-based slicing (don't buffer whole data); yield chunks if needed |
| Breaking existing SMB1 users | Preserve `SMB.__hdr__` and all existing public attributes; add new features without removal |

---

*End of Design Specification*
