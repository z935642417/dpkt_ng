# $Id: smb.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Server Message Block."""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt
import struct


# https://msdn.microsoft.com/en-us/library/ee441774.aspx

SMB_FLAGS_LOCK_AND_READ_OK = 0x01
SMB_FLAGS_BUF_AVAIL = 0x02
SMB_FLAGS_CASE_INSENSITIVE = 0x08
SMB_FLAGS_CANONICALIZED_PATHS = 0x10
SMB_FLAGS_OPLOCK = 0x20
SMB_FLAGS_OPBATCH = 0x40
SMB_FLAGS_REPLY = 0x80

SMB_FLAGS2_LONG_NAMES = 0x0001
SMB_FLAGS2_EXTENDED_ATTRIBUTES = 0x0002
SMB_FLAGS2_SECURITY_SIGNATURES = 0x0004
SMB_FLAGS2_COMPRESSED = 0x0008
SMB_FLAGS2_SECURITY_SIGNATURES_REQUIRED = 0x0010
SMB_FLAGS2_IS_LONG_NAME = 0x0040
SMB_FLAGS2_REVERSE_PATH = 0x0400
SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
SMB_FLAGS2_DFS = 0x1000
SMB_FLAGS2_PAGING_IO = 0x2000
SMB_FLAGS2_NT_STATUS = 0x4000
SMB_FLAGS2_UNICODE = 0x8000

SMB_STATUS_SUCCESS = 0x00000000

# SMB1 Command codes
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


class SMB(dpkt.Packet):
    r"""Server Message Block.

    Server Message Block (SMB) is a communication protocol[1] that Microsoft created for providing
    shared access to files and printers across nodes on a network. It also provides an authenticated
    inter-process communication (IPC) mechanism.

    Attributes:
        __hdr__: SMB Headers
            proto: (bytes): Protocol. This field MUST contain the 4-byte literal string '\xFF', 'S', 'M', 'B' (4 bytes)
            cmd: (int): Command. Defines SMB command. (1 byte)
            status: (int): Status. Communicates error messages from the server to the client. (4 bytes)
            flags: (int): Flags. Describes various features in effect for the message.(1 byte)
            flags2: (int): Flags2. Represent various features in effect for the message.
                Unspecified bits are reserved and MUST be zero. (2 bytes)
            _pidhi: (int): PIDHigh. Represents the high-order bytes of a process identifier (PID) (2 bytes)
            security: (bytes): SecurityFeatures. Has three possible interpretations. (8 bytes)
            rsvd: (int): Reserved. This field is reserved and SHOULD be set to 0x0000. (2 bytes)
            tid: (int): TID. A tree identifier (TID). (2 bytes)
            _pidlo: (int): PIDLow. The lower 16-bits of the PID. (2 bytes)
            uid: (int): UID. A user identifier (UID). (2 bytes)
            mid: (int): MID. A multiplex identifier (MID).(2 bytes)
    """

    __byte_order__ = '<'
    __hdr__ = [
        ('proto', '4s', b'\xffSMB'),
        ('cmd', 'B', 0),
        ('status', 'I', SMB_STATUS_SUCCESS),
        ('flags', 'B', 0),
        ('flags2', 'H', 0),
        ('_pidhi', 'H', 0),
        ('security', '8s', b''),
        ('rsvd', 'H', 0),
        ('tid', 'H', 0),
        ('_pidlo', 'H', 0),
        ('uid', 'H', 0),
        ('mid', 'H', 0)
    ]

    @property
    def pid(self):
        return (self._pidhi << 16) | self._pidlo

    @pid.setter
    def pid(self, v):
        self._pidhi = v >> 16
        self._pidlo = v & 0xffff

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
            try:
                cmd = cmd_cls(buf[offset:])
                self.commands.append(cmd)
                next_cmd = getattr(cmd, 'andx_command', 0xFF)
                andx_off = getattr(cmd, 'andx_offset', 0)
                if next_cmd == 0xFF or andx_off == 0:
                    break
                offset = offset + andx_off
            except (dpkt.UnpackError, struct.error, IndexError):
                break
        self.data = b''


class SMB1Command(dpkt.Packet):
    """Base class for all SMB1 commands using WordCount/ByteCount pattern."""
    __byte_order__ = '<'

    def __init__(self, *args, **kwargs):
        self.andx_command = 0xFF
        self.andx_offset = 0
        super(SMB1Command, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        self.word_count = buf[0]
        params_start = 1
        params_end = params_start + self.word_count * 2
        self._params = buf[params_start:params_end]
        bc_off = params_end
        self.byte_count = struct.unpack('<H', buf[bc_off:bc_off + 2])[0]
        data_off = bc_off + 2
        self._raw_data = buf[data_off:data_off + self.byte_count]
        self.data = b''

    def __bytes__(self):
        wc = getattr(self, 'word_count', 0)
        params = getattr(self, '_params', b'')
        bc = getattr(self, 'byte_count', None)
        raw_data = getattr(self, '_raw_data', b'')
        if bc is None:
            bc = len(raw_data)
        return struct.pack('<B', wc) + params + struct.pack('<H', bc) + raw_data

    def __len__(self):
        return 1 + len(getattr(self, '_params', b'')) + 2 + len(getattr(self, '_raw_data', b''))


class SMB1Negotiate(SMB1Command):
    """SMB1 Negotiate Protocol."""

    def unpack(self, buf):
        self.word_count = buf[0]
        params_start = 1
        if self.word_count > 0:
            self._params = buf[params_start:params_start + self.word_count * 2]
        else:
            self._params = b''
        params_end = params_start + self.word_count * 2
        bc_off = params_end
        self.byte_count = struct.unpack('<H', buf[bc_off:bc_off + 2])[0]
        data_off = bc_off + 2
        self._raw_data = buf[data_off:data_off + self.byte_count]
        self.dialects = []
        if self.word_count == 0 and self._raw_data:
            d = self._raw_data
            while d:
                try:
                    end = d.index(b'\x00')
                    self.dialects.append(d[:end])
                    d = d[end + 1:]
                except ValueError:
                    if len(d) > 0:
                        self.dialects.append(d)
                    break
        self.data = b''


class SMB1SessionSetupAndX(SMB1Command):
    """SMB1 Session Setup AndX."""

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]


class SMB1TreeConnectAndX(SMB1Command):
    """SMB1 Tree Connect AndX."""

    def __init__(self, *args, **kwargs):
        self.path = b''
        self.service = b''
        super(SMB1TreeConnectAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        if len(self._params) >= 6:
            self.flags = struct.unpack('<H', self._params[4:6])[0]
        if self._raw_data:
            parts = self._raw_data.split(b'\x00', 1)
            self.path = parts[0] if len(parts) > 0 else b''
            self.service = parts[1] if len(parts) > 1 else b''


class SMB1NTCreateAndX(SMB1Command):
    """SMB1 NT Create AndX."""

    def __init__(self, *args, **kwargs):
        self.file_name = b''
        super(SMB1NTCreateAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        if len(self._params) >= 28:
            self.name_length = struct.unpack('<H', self._params[20:22])[0]
            if self.name_length and len(self._raw_data) >= self.name_length + 1:
                self.file_name = self._raw_data[1:1 + self.name_length]


class SMB1Close(SMB1Command):
    """SMB1 Close."""

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)


class SMB1ReadAndX(SMB1Command):
    """SMB1 Read AndX."""

    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB1ReadAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        if len(self._params) >= 24:
            self.fid = struct.unpack('<H', self._params[4:6])[0]
            self.offset = struct.unpack('<I', self._params[6:10])[0]
            self.max_count = struct.unpack('<H', self._params[10:12])[0]
        self.file_data = self._raw_data
        self.data = b''


class SMB1WriteAndX(SMB1Command):
    """SMB1 Write AndX."""

    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB1WriteAndX, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]
        if len(self._params) >= 28:
            self.fid = struct.unpack('<H', self._params[4:6])[0]
            self.offset = struct.unpack('<I', self._params[6:10])[0]
            self.timeout = struct.unpack('<I', self._params[10:14])[0]
            self.write_mode = struct.unpack('<H', self._params[14:16])[0]
            self.remaining = struct.unpack('<H', self._params[16:18])[0]
            self.data_length = struct.unpack('<H', self._params[20:22])[0]
            self.data_offset = struct.unpack('<H', self._params[22:24])[0]
        self.file_data = self._raw_data
        self.data = b''


class SMB1Open(SMB1Command):
    """SMB1 Open (legacy)."""
    pass


class SMB1OpenAndX(SMB1Command):
    """SMB1 Open AndX."""

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]


class SMB1LogoffAndX(SMB1Command):
    """SMB1 Logoff AndX."""

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 4:
            self.andx_command = self._params[0]
            self._andx_rsv = self._params[1]
            self.andx_offset = struct.unpack('<H', self._params[2:4])[0]


class SMB1Echo(SMB1Command):
    """SMB1 Echo."""
    pass


class SMB1TreeDisconnect(SMB1Command):
    """SMB1 Tree Disconnect."""
    pass


class SMB1Trans2(SMB1Command):
    """SMB1 Transaction2."""
    _subcmdsw = {}

    def __init__(self, *args, **kwargs):
        self.sub_cmd = None
        self.param_data = b''
        super(SMB1Trans2, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 28:
            self.total_param_count = struct.unpack('<H', self._params[0:2])[0]
            self.total_data_count = struct.unpack('<H', self._params[2:4])[0]
            self.max_param_count = struct.unpack('<H', self._params[4:6])[0]
            self.max_data_count = struct.unpack('<H', self._params[6:8])[0]
            self.max_setup_count = self._params[8]
            self._rsv1 = self._params[9]
            self.flags = struct.unpack('<H', self._params[10:12])[0]
            self.timeout = struct.unpack('<I', self._params[12:16])[0]
            self._rsv2 = struct.unpack('<H', self._params[16:18])[0]
            self.param_count = struct.unpack('<H', self._params[18:20])[0]
            self.param_offset = struct.unpack('<H', self._params[20:22])[0]
            self.data_count = struct.unpack('<H', self._params[22:24])[0]
            self.data_offset = struct.unpack('<H', self._params[24:26])[0]
            setup_count = self._params[26]
            self._rsv3 = self._params[27]
            setup_end = 28 + setup_count * 2
            if setup_end <= len(self._params):
                self.setup = self._params[28:setup_end]
                if setup_count >= 1 and len(self.setup) >= 2:
                    self.sub_cmd = struct.unpack('<H', self.setup[0:2])[0]
            if self.param_count and self.param_offset >= 32:
                param_start = self.param_offset - 32
                self.param_data = self._raw_data[param_start:param_start + self.param_count] if param_start < len(self._raw_data) else b''
        self.data = b''


class SMB1Trans(SMB1Command):
    """SMB1 Transaction."""
    _subcmdsw = {}

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        self.data = b''


class SMB1NTTrans(SMB1Command):
    """SMB1 NT Transaction."""
    _subcmdsw = {}

    def unpack(self, buf):
        SMB1Command.unpack(self, buf)
        if len(self._params) >= 38:
            self.setup_count = self._params[32] if len(self._params) > 32 else 0
            if self.setup_count >= 1 and len(self._params) >= 36:
                self.function_code = struct.unpack('<H', self._params[34:36])[0]
            else:
                self.function_code = 0
        self.data = b''


class SMB1NTTransSecondary(SMB1Command):
    """SMB1 NT Transaction Secondary."""
    pass


def _mod_init():
    """Post-import hook: populate SMB._cmdsw from SMB_CMD_* constants."""
    for name, val in list(globals().items()):
        if name.startswith('SMB_CMD_'):
            suffix = name[len('SMB_CMD_'):]
            parts = suffix.split('_')
            for i, part in enumerate(parts):
                if part == 'NT':
                    continue
                elif part == 'ANDX':
                    parts[i] = 'AndX'
                else:
                    parts[i] = part.capitalize()
            cls_name = 'SMB1' + ''.join(parts)
            cmd_cls = globals().get(cls_name)
            if cmd_cls is not None and isinstance(cmd_cls, type) and issubclass(cmd_cls, SMB1Command):
                SMB._cmdsw[val] = cmd_cls


_mod_init()


def test_smb():
    buf = (b'\xffSMB\xa0\x00\x00\x00\x00\x08\x03\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x08\xfa\x7a\x00\x08\x53\x02')
    smb = SMB(buf)

    assert smb.flags == SMB_FLAGS_CASE_INSENSITIVE
    assert smb.flags2 == (SMB_FLAGS2_UNICODE | SMB_FLAGS2_NT_STATUS |
                          SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_EXTENDED_ATTRIBUTES | SMB_FLAGS2_LONG_NAMES)
    assert smb.pid == 31482
    assert smb.uid == 2048
    assert smb.mid == 595
    print(repr(smb))

    smb = SMB()
    smb.pid = 0x00081020
    smb.uid = 0x800
    assert str(smb) == str(b'\xffSMB\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x00\x00\x20\x10\x00\x08\x00\x00')


def test_smb1_andx_chain():
    """Test SMB1 ANDX chain detection (TreeConnectAndX registered)."""
    buf = (b'\xffSMB\x75\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\xff\x00'
           b'\x00\x00')
    smb = SMB(buf)
    assert smb.proto == b'\xffSMB'
    assert len(smb.commands) == 1


def test_smb1_negotiate():
    """SMB1 Negotiate should parse dialects."""
    buf = (b'\xffSMB\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x17\x00'
           b'PC NETWORK PROGRAM 1.0\x00')
    smb = SMB(buf)
    assert len(smb.commands) == 1
    assert isinstance(smb.commands[0], SMB1Negotiate)
    assert b'PC NETWORK PROGRAM 1.0' in smb.commands[0].dialects


def test_smb1_nt_create_andx():
    """SMB1 NTCreateAndX with file name."""
    buf = (b'\xffSMB\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x18'
           b'\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           b'\x0a\x00'
           b'\x00test.txt\x00')
    parsed = SMB(buf)
    assert len(parsed.commands) == 1
    assert isinstance(parsed.commands[0], SMB1NTCreateAndX)


def test_smb1_read_andx():
    """SMB1 ReadAndX with file data in response."""
    smb = SMB(cmd=SMB_CMD_READ_ANDX)
    cmd = SMB1ReadAndX()
    cmd.word_count = 12
    cmd._params = b'\xff\x00\x00\x00' + b'\x00' * 20
    cmd.andx_command = 0xFF
    cmd._raw_data = b'Hello World'
    cmd.byte_count = 11
    cmd.file_data = b'Hello World'
    smb.data = cmd
    data = bytes(smb)
    parsed = SMB(data)
    assert len(parsed.commands) == 1
    assert isinstance(parsed.commands[0], SMB1ReadAndX)
    assert parsed.commands[0].file_data == b'Hello World'
