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
            except (dpkt.UnpackError, struct.error):
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


SMB._cmdsw[SMB_CMD_NEGOTIATE] = SMB1Negotiate
SMB._cmdsw[SMB_CMD_SESSION_SETUP_ANDX] = SMB1SessionSetupAndX
SMB._cmdsw[SMB_CMD_TREE_CONNECT_ANDX] = SMB1TreeConnectAndX
SMB._cmdsw[SMB_CMD_NT_CREATE_ANDX] = SMB1NTCreateAndX
SMB._cmdsw[SMB_CMD_CLOSE] = SMB1Close


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
