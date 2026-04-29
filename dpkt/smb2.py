# -*- coding: utf-8 -*-
"""Server Message Block version 2."""
from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt

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
        ('_status', 'I', 0),
        ('cmd', 'H', 0),
        ('credit_req', 'H', 0),
        ('_flags_val', 'I', 0),
        ('next_cmd', 'I', 0),
        ('mid', 'Q', 0),
        ('pid', 'I', 0),
        ('tid', 'I', 0),
        ('sid', 'Q', 0),
        ('sig', '16s', b'\x00' * 16),
    ]
    __bit_fields__ = {
        '_flags_val': (
            ('_rsv_hi', 2),
            ('replay', 1),
            ('dfs', 1),
            ('_rsv_mid', 21),
            ('priority', 3),
            ('signed', 1),
            ('related', 1),
            ('async', 1),
            ('response', 1),
        ),
    }
    _cmdsw = {}

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            cmd_cls = self._cmdsw[self.cmd]
            self.data = cmd_cls(buf[self.__hdr_len__:])
            attr_name = self.data.__class__.__name__.lower().replace('smb2', '', 1)
            setattr(self, attr_name, self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf[self.__hdr_len__:]


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
        ('_flags_val', 'H', 0),
        ('path_offset', 'H', 0),
        ('path_length', 'H', 0),
    ]
    __bit_fields__ = {
        '_flags_val': (
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
        start = self.path_offset - 64
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
        start = self.name_offset - 64
        self.file_name = buf[start:start + self.name_length]
        self.data = b''


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
    """SMB2 READ Request/Response. Handles both via StructureSize detection."""
    __byte_order__ = '<'

    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB2Read, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        if len(buf) < 2:
            raise dpkt.UnpackError('invalid SMB2Read buffer length %d' % len(buf))
        struct_size = struct.unpack('<H', buf[0:2])[0]
        if struct_size == 17:
            self._unpack_response(buf)
        elif struct_size == 49:
            self._unpack_request(buf)
        else:
            raise dpkt.UnpackError('invalid SMB2Read StructureSize %d' % struct_size)

    def _unpack_response(self, buf):
        self.struct_size, self.data_offset = struct.unpack('<HB', buf[0:3])
        self._rsv = buf[3]
        self.data_length, self.data_remaining = struct.unpack('<II', buf[4:12])
        self._rsv2 = buf[12:16]
        start = self.data_offset - 64
        self.file_data = buf[start:start + self.data_length]
        self.data = b''

    def _unpack_request(self, buf):
        self.struct_size = struct.unpack('<H', buf[0:2])[0]
        self.padding = buf[2]
        self._flags = buf[3]
        self.length = struct.unpack('<I', buf[4:8])[0]
        self.offset = struct.unpack('<Q', buf[8:16])[0]
        self.file_id = buf[16:32]
        self.minimum_count = struct.unpack('<I', buf[32:36])[0]
        self.channel = struct.unpack('<I', buf[36:40])[0]
        self.remaining = struct.unpack('<I', buf[40:44])[0]
        self.channel_info_offset = struct.unpack('<H', buf[44:46])[0]
        self.channel_info_length = struct.unpack('<H', buf[46:48])[0]
        self.flags = struct.unpack('<I', buf[48:52])[0] if len(buf) >= 52 else 0
        self.data = b''

    def __bytes__(self):
        if hasattr(self, 'struct_size') and self.struct_size == 17:
            return self._pack_response()
        return self._pack_request()

    def _pack_response(self):
        return struct.pack('<HBBII4s',
            getattr(self, 'struct_size', 17),
            getattr(self, 'data_offset', 0),
            getattr(self, '_rsv', 0),
            getattr(self, 'data_length', len(self.file_data)),
            getattr(self, 'data_remaining', 0),
            getattr(self, '_rsv2', b'\x00' * 4)) + self.file_data

    def _pack_request(self):
        return struct.pack('<HBBIQ16sIIIHHI',
            getattr(self, 'struct_size', 49),
            getattr(self, 'padding', 0),
            getattr(self, '_flags', 0),
            getattr(self, 'length', 0),
            getattr(self, 'offset', 0),
            getattr(self, 'file_id', b'\xff' * 16),
            getattr(self, 'minimum_count', 0),
            getattr(self, 'channel', 0),
            getattr(self, 'remaining', 0),
            getattr(self, 'channel_info_offset', 0),
            getattr(self, 'channel_info_length', 0),
            getattr(self, 'flags', 0))


class SMB2Write(dpkt.Packet):
    """SMB2 WRITE Request/Response."""
    __byte_order__ = '<'

    def __init__(self, *args, **kwargs):
        self.file_data = b''
        super(SMB2Write, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        struct_size = struct.unpack('<H', buf[0:2])[0]
        if struct_size == 17:
            self._unpack_response(buf)
        else:
            self._unpack_request(buf)

    def _unpack_request(self, buf):
        self.struct_size = struct.unpack('<H', buf[0:2])[0]
        self.data_offset = struct.unpack('<H', buf[2:4])[0]
        self.length = struct.unpack('<I', buf[4:8])[0]
        self.offset = struct.unpack('<Q', buf[8:16])[0]
        self.file_id = buf[16:32]
        self.channel = struct.unpack('<I', buf[32:36])[0]
        self.remaining = struct.unpack('<I', buf[36:40])[0]
        self.channel_info_offset = struct.unpack('<H', buf[40:42])[0]
        self.channel_info_length = struct.unpack('<H', buf[42:44])[0]
        self.write_flags = struct.unpack('<I', buf[44:48])[0] if len(buf) >= 48 else 0
        start = self.data_offset - 64
        self.file_data = buf[start:start + self.length]
        self.data = b''

    def _unpack_response(self, buf):
        self.struct_size = struct.unpack('<H', buf[0:2])[0]
        self._rsv = struct.unpack('<H', buf[2:4])[0]
        self.count = struct.unpack('<I', buf[4:8])[0]
        self.remaining = struct.unpack('<I', buf[8:12])[0]
        self.channel_info_offset = struct.unpack('<H', buf[12:14])[0]
        self.channel_info_length = struct.unpack('<H', buf[14:16])[0]
        self.data = b''

    def __bytes__(self):
        if hasattr(self, 'struct_size') and self.struct_size == 17:
            return self._pack_response()
        return self._pack_request()

    def _pack_request(self):
        return struct.pack('<HHIQ16sIIHHI',
            getattr(self, 'struct_size', 49),
            getattr(self, 'data_offset', 0),
            getattr(self, 'length', len(self.file_data)),
            getattr(self, 'offset', 0),
            getattr(self, 'file_id', b'\xff' * 16),
            getattr(self, 'channel', 0),
            getattr(self, 'remaining', 0),
            getattr(self, 'channel_info_offset', 0),
            getattr(self, 'channel_info_length', 0),
            getattr(self, 'write_flags', 0)) + self.file_data

    def _pack_response(self):
        return struct.pack('<HHIIHH',
            getattr(self, 'struct_size', 17),
            getattr(self, '_rsv', 0),
            getattr(self, 'count', 0),
            getattr(self, 'remaining', 0),
            getattr(self, 'channel_info_offset', 0),
            getattr(self, 'channel_info_length', 0))


def _mod_init():
    for name, val in list(globals().items()):
        if name.startswith('SMB2_CMD_'):
            cls_name = 'SMB2' + name[len('SMB2_CMD_'):].title().replace('_', '')
            cmd_cls = globals().get(cls_name)
            if cmd_cls is not None and isinstance(cmd_cls, type):
                SMB2._cmdsw[val] = cmd_cls


_mod_init()


def test_smb2_header():
    """Verify SMB2 64-byte header unpack."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d424000' + '0000' * 29
    )
    smb2 = SMB2(buf)
    assert smb2.proto == b'\xfeSMB'
    assert smb2.hdr_len == 64
    assert smb2.cmd == 0
    assert len(bytes(smb2)) == 64


def test_smb2_flags():
    """Test SMB2 flag bit fields."""
    smb2 = SMB2()
    assert smb2.response == 0
    smb2.response = 1
    assert smb2.response == 1
    assert (smb2._flags_val & 1) == 1
    smb2.signed = 1
    assert smb2.signed == 1
    assert smb2.response == 1
    smb2.dfs = 1
    assert smb2.dfs == 1
    smb2.replay = 1
    assert smb2.replay == 1
    setattr(smb2, 'async', 1)
    assert getattr(smb2, 'async') == 1
    smb2.related = 1
    assert smb2.related == 1
    assert smb2.response == 1
    assert smb2.signed == 1


def test_smb2_roundtrip():
    """Test SMB2 pack → unpack → bytes."""
    smb2 = SMB2(cmd=SMB2_CMD_READ, mid=1, pid=0x1234, tid=0x5678, sid=0x9ABC)
    data = bytes(smb2)
    assert len(data) == 64
    parsed = SMB2(data)
    assert parsed.cmd == SMB2_CMD_READ
    assert parsed.mid == 1
    assert parsed.pid == 0x1234
    assert parsed.tid == 0x5678
    assert parsed.sid == 0x9ABC


def test_smb2_negotiate_request():
    """Test SMB2 NEGOTIATE request parsing."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d424000' + '0000' * 29  # SMB2 header (64 zero bytes, cmd=0)
        + '2400' + '0500' + '0000' * 6 + '00000000000000000000000000000000'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_NEGOTIATE
    assert isinstance(smb2.data, SMB2Negotiate)
    assert smb2.data.struct_size == 36


def test_smb2_negotiate_roundtrip():
    """Test SMB2 NEGOTIATE construct → bytes → parse."""
    nego = SMB2Negotiate(dialect_count=2, security_mode=1, capabilities=0x1F)
    smb2 = SMB2(cmd=SMB2_CMD_NEGOTIATE, data=nego)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert isinstance(parsed.data, SMB2Negotiate)
    assert parsed.data.dialect_count == 2


def test_smb2_session_setup():
    """Test SMB2 SESSION_SETUP parsing."""
    ss = SMB2SessionSetup(struct_size=25, security_blob_offset=74)
    smb2 = SMB2(cmd=SMB2_CMD_SESSION_SETUP, data=ss)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert parsed.cmd == SMB2_CMD_SESSION_SETUP
    assert isinstance(parsed.data, SMB2SessionSetup)
    assert parsed.data.struct_size == 25


def test_smb2_tree_connect():
    """Test SMB2 TREE_CONNECT parsing."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d4240000000000000000300000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '09000000080000005c005c004900500043002400'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_TREE_CONNECT
    assert isinstance(smb2.data, SMB2TreeConnect)


def test_smb2_create():
    """Test SMB2 CREATE parsing."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d4240000000000000000500000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '3900000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000066006f00'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_CREATE
    assert isinstance(smb2.data, SMB2Create)


def test_smb2_close():
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d4240000000000000000600000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '18000000ffffffffffffffffffffffffffffffff'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == SMB2_CMD_CLOSE
    assert isinstance(smb2.data, SMB2Close)


def test_smb2_read_response():
    """Test SMB2 READ response with file data extraction."""
    read_resp = SMB2Read()
    read_resp.struct_size = 17
    read_resp.data_offset = 80
    read_resp._rsv = 0
    read_resp.data_length = 11
    read_resp.data_remaining = 0
    read_resp._rsv2 = b'\x00' * 4
    read_resp.file_data = b'Hello World'

    smb2 = SMB2(cmd=SMB2_CMD_READ, mid=1, data=read_resp)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert parsed.cmd == SMB2_CMD_READ
    assert isinstance(parsed.data, SMB2Read)
    assert parsed.data.file_data == b'Hello World'


def test_smb2_read_request_roundtrip():
    """Test SMB2 READ request construct -> bytes -> parse."""
    read_req = SMB2Read()
    read_req.struct_size = 49
    read_req.padding = 0x50
    read_req._flags = 0
    read_req.length = 4096
    read_req.offset = 0
    read_req.file_id = b'\xff' * 16
    read_req.minimum_count = 1
    read_req.channel = 0
    read_req.remaining = 0
    read_req.channel_info_offset = 0
    read_req.channel_info_length = 0
    read_req.flags = 0

    smb2 = SMB2(cmd=SMB2_CMD_READ, mid=1, data=read_req)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert isinstance(parsed.data, SMB2Read)
    assert parsed.data.struct_size == 49
    assert parsed.data.length == 4096
    assert parsed.data.minimum_count == 1


def test_smb2_close_roundtrip():
    """Test SMB2 CLOSE construct -> bytes -> parse."""
    close = SMB2Close(flags=1, file_id=b'\x01' * 16)
    smb2 = SMB2(cmd=SMB2_CMD_CLOSE, mid=1, data=close)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert isinstance(parsed.data, SMB2Close)
    assert parsed.data.flags == 1


def test_smb2_write_request():
    """Test SMB2 WRITE request with file data extraction."""
    write_req = SMB2Write()
    write_req.struct_size = 49
    write_req.data_offset = 112  # 64 (SMB2 header) + 48 (Write header)
    write_req.length = 11
    write_req.offset = 0
    write_req.file_id = b'\xff' * 16
    write_req.channel = 0
    write_req.remaining = 0
    write_req.channel_info_offset = 0
    write_req.channel_info_length = 0
    write_req.write_flags = 0
    write_req.file_data = b'Hello World'

    smb2 = SMB2(cmd=SMB2_CMD_WRITE, mid=1, data=write_req)
    data = bytes(smb2)
    parsed = SMB2(data)
    assert parsed.cmd == SMB2_CMD_WRITE
    assert isinstance(parsed.data, SMB2Write)
    assert parsed.data.file_data == b'Hello World'


def test_smb2_unknown_command():
    """Test unknown command falls back to raw bytes."""
    from binascii import unhexlify
    buf = unhexlify(
        'fe534d424000000000000000ff00000000000000'
        '0000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000'
        '00000000deadbeef'
    )
    smb2 = SMB2(buf)
    assert smb2.cmd == 0x00FF
    assert isinstance(smb2.data, bytes)
    assert smb2.data == b'\xde\xad\xbe\xef'


def test_smb2_mod_init():
    """Verify _mod_init() populates _cmdsw."""
    assert SMB2_CMD_NEGOTIATE in SMB2._cmdsw
    assert SMB2_CMD_READ in SMB2._cmdsw
    assert SMB2_CMD_WRITE in SMB2._cmdsw
    assert SMB2_CMD_CLOSE in SMB2._cmdsw
    assert SMB2._cmdsw[SMB2_CMD_NEGOTIATE] is SMB2Negotiate
